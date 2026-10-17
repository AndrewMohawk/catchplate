"""One same-permission grant acquisition followed by genuine token receiving.

No authority or target enters as a caller argument. The raw8 contains actual
proof/intent/possession and proof-bound ciphertext only; its raw2 is retained by
the existing handoff before semantic admission. Neither request nor token is
journaled, and neither lost replies nor retained grants restore permission.
"""
from __future__ import annotations

from catchplate import authority_oidc_session_activation_release_grant_transport as transport
from catchplate import control_plane_oidc_session_activation_release_grant_acquisition_bootstrap as configured
from catchplate import control_plane_oidc_session_activation_release_handoff as handoff


execution, planning, hints = handoff.execution, handoff.planning, handoff.hints
clients, delivery, plan = handoff.clients, handoff.delivery, handoff.plan


def _acquire_on_permission(permission, *, _delivery=None):
    """Receive only through the actual active, already proof-verified owner."""
    if type(permission) is not execution._ActivationPermission:
        execution._fail("release grant acquisition requires the actual permission")
    permission._identity()
    owner, work = permission._owner, permission._work
    parent, binding, custody = owner._material, owner._binding, owner._custody
    policy, client_policy = parent.release_grant_acquisition, parent.release_handoff
    proof_policy, intent_policy = parent.release_proof, parent.release_intent
    proof_raw, context = permission._release_proof_originals, permission._release_proof_context
    intent_raw, hint_raw = permission._release_intent_original, permission._consume_completion_hints
    possession, target = permission._consume_possession, permission._target
    if (permission._state != "active" or permission._dispatch_phase != "release-handoff-requesting"
            or permission._release_handoff_spent is not True
            or type(policy) is not configured._ReleaseGrantAcquisitionMaterial
            or type(client_policy) is not handoff.configured._ReleaseHandoffMaterial
            or type(proof_policy) is not handoff.proof_config._ReleaseProofMaterial
            or type(intent_policy) is not handoff.intent_config._ReleaseIntentMaterial
            or proof_raw is not permission._release_proof_seal or proof_raw[0] != b"proved"
            or context is not permission._release_proof_context_seal
            or intent_raw is not permission._release_intent_seal
            or hint_raw is not permission._consume_completion_hints_seal
            or possession is not permission._consume_possession_seal
            or (binding.caller_uid, binding.caller_gid) != (clients.CLIENT_UID, clients.CLIENT_GID)):
        execution._fail("release grant acquisition lacks its original verified continuation")
    endpoint = transport._endpoint(policy.endpoint)
    release_raw, prior_current, _prior_narrow, prior_bytes = context
    proof_enrollment, intent_enrollment = proof_policy.enrollment_bytes, intent_policy.enrollment_bytes
    client_id = client_policy.client_id
    identity_raw, client_endpoint_raw = client_policy.client_identity_bytes, client_policy.endpoint_bytes
    root, response_pin = binding.runtime_root_public_key, owner._response_pin
    target_digest = target[2]["localDigest"]
    cookie = permission._request.cookies.get(possession[0])
    if (type(cookie) is not str or cookie != possession[1] or len(cookie) != delivery.TOKEN_BYTES
            or any(ord(character) > 127 for character in cookie)):
        execution._fail("release grant acquisition lost its actual old-token possession")
    handoff.capture._SharedLedger(work)
    limits, metrics = work.limits, work.metrics
    ceilings = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes

    def current():
        nonlocal metrics
        if (permission._owner is not owner or permission._work is not work
                or owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or binding.runtime_root_public_key is not root or owner._response_pin != response_pin
                or parent.release_grant_acquisition is not policy or policy.endpoint != endpoint
                or parent.release_handoff is not client_policy or client_policy.client_id != client_id
                or client_policy.client_identity_bytes is not identity_raw
                or client_policy.endpoint_bytes is not client_endpoint_raw
                or parent.release_proof is not proof_policy or proof_policy.enrollment_bytes is not proof_enrollment
                or parent.release_intent is not intent_policy or intent_policy.enrollment_bytes is not intent_enrollment
                or permission._release_proof_originals is not proof_raw or permission._release_proof_context is not context
                or permission._release_intent_original is not intent_raw
                or permission._consume_completion_hints is not hint_raw
                or permission._consume_possession is not possession or permission._target is not target
                or target[2]["localDigest"] != target_digest
                or permission._request.cookies.get(possession[0]) != cookie
                or permission._dispatch_phase != "release-handoff-requesting"
                or permission._release_handoff_spent is not True):
            execution._fail("release grant acquisition changed its original owner or inputs")
        handoff.capture._SharedLedger(work)
        observed = work.metrics
        if (work.limits is not limits
                or ceilings != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                or observed.hash_work < metrics.hash_work or observed.input_bytes < metrics.input_bytes
                or observed.json_nodes < metrics.json_nodes):
            execution._fail("release grant acquisition reset its original work allowance")
        metrics = observed
        return prior_current()

    current()
    work.charge(input_bytes=len(cookie))
    old = delivery._token(cookie.encode("ascii"), work)
    planning._same_bytes(proof_raw[3], proof_enrollment, work,
        "release grant acquisition independently enrolled proof original")
    release = planning.activation._object(release_raw, handoff.intents.contract.MAX_BYTES, work)
    packet, effects, envelope, created, expires = hints._decode_on_work(hint_raw, work=work)
    for actual, expected, label in (
            (packet, release["consumeBinding"]["packetDigest"], "packet"),
            (effects, release["consumeBinding"]["effectsDigest"], "effects"),
            (created, release["deliveryScope"]["createdAt"], "created"),
            (expires, release["deliveryScope"]["expiresAt"], "expires"),
            (planning.assertion._digest(envelope, work), release["deliveryEnvelopeDigest"], "ciphertext")):
        plan._same(actual, expected, work, "release grant acquisition proof-bound hint " + label)
    current()
    request = transport._originals((transport.PURPOSE, handoff.transport.LIVE_PURPOSE,
        proof_raw[2], proof_raw[3], intent_raw, intent_enrollment, old, envelope), response=False)
    # Reserve the complete remaining input inventory before issuer contact;
    # the handoff receives only an additional byte charge, never new authority.
    request_bytes = sum(map(len, request)) - len(transport.PURPOSE)
    additional = sum(map(len, request)) + transport.REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES
    remaining = (len(identity_raw) + len(client_endpoint_raw) + clients.MAX_BYTES + handoff.outcomes.MAX_BYTES
        + request_bytes + handoff.transport.LIVE_REQUEST_HEADER_BYTES
        + handoff.transport.RESPONSE_HEADER_BYTES + handoff.transport.MAX_RESPONSE_BYTES)
    if prior_bytes + additional + transport.MAX_RESPONSE_BYTES + remaining > handoff.receiving.MAX_ORIGINAL_BYTES:
        execution._fail("release grant acquisition exceeds the original whole-call inventory")
    current()
    _window, bound = permission._planning_bounds
    response = transport._socket_request_on_work(endpoint, originals=request, deadline_ns=bound,
        work=work, current=current)
    current()
    response = transport._originals(response, response=True)
    # The existing raw2 retention runs before semantic admission, including
    # empty/malformed grant bytes. Its final genuine receiver retains current.
    return handoff._release_on_permission(permission, client_authorization_bytes=response[0],
        server_bootstrap_bytes=response[1], _current=current, _additional_original_bytes=additional,
        _delivery=_delivery)
