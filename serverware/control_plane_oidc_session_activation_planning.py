"""One genuine post-permission planner exchange and original authorization.

The active parent context owns permission, keys and clocks. This module holds
only public planner configuration and original request data; it receives no
success carrier, history key, execution grant or token-release authority.
"""
from __future__ import annotations

from serverware import authority_oidc_session_activation_planner_transport as transport
from serverware import control_plane_oidc_session_activation_planning_bootstrap as configured
from serverware import control_plane_oidc_session_activation_dispatch_attempt as attempts
from serverware import control_plane_oidc_session_activation_execution as execution
from serverware import control_plane_registration_finalization_completion_pending as pending


caller, planner = execution.caller, configured.planner
assertion, registration = caller.activation.assertion, caller.activation.registration
capture, production, plan = execution.capture, execution.production, execution.plan
MAX_ASSERTION_BYTES = assertion.MAX_ASSERTION_BYTES


def _planning_inputs(assertion_bytes, expected_challenge_id):
    """Bound immutable external inputs before entering permission callbacks."""
    if (type(assertion_bytes) is not bytes or not 2 <= len(assertion_bytes) <= MAX_ASSERTION_BYTES
            or type(expected_challenge_id) is not str
            or not 1 <= len(expected_challenge_id) <= 1024
            or "\x00" in expected_challenge_id
            or any(0xD800 <= ord(point) <= 0xDFFF for point in expected_challenge_id)):
        execution._fail("activation planning requires bounded original assertion and challenge ID")
    return assertion_bytes, expected_challenge_id


def _object(raw, maximum, work):
    value = caller.activation.evidence.wire._decode_object(raw, work=work,
        maximum_bytes=maximum, maximum_nodes=assertion.MAX_CONTEXT_NODES, maximum_depth=12)
    canonical = registration._wire(value, work)
    work.charge(input_bytes=len(raw) + len(canonical))
    if raw != canonical:
        execution._fail("activation planner response is not an exact canonical original")
    return value


def _prepare_on_permission(permission, *, assertion_bytes, expected_challenge_id):
    """Private same-call composition; returned data is never permission proof."""
    if type(permission) is not execution._ActivationPermission:
        execution._fail("activation planning requires the actual active permission context")
    permission._identity()
    if (permission._state != "active" or permission._planning_spent is not True
            or permission._spent is not False):
        execution._fail("activation planning is not this context's single preparation")
    original_assertion, challenge_id = _planning_inputs(assertion_bytes, expected_challenge_id)
    owner, work, scope = permission._owner, permission._work, permission._scope
    parent, binding, custody_owner = owner._material, owner._binding, owner._custody
    policy = parent.activation_planning
    caller_policy = parent.activation_execution
    from serverware import control_plane_oidc_session_activation_request_issuance_bootstrap as request_configuration
    dynamic = type(policy) is request_configuration._RequestPlanningMaterial
    if not dynamic and type(policy) is not configured._PlanningMaterial:
        execution._fail("activation planning is not independently root configured")
    original_bootstrap = None if dynamic else policy.planner_bootstrap_bytes
    endpoint = policy.planner_endpoint
    if not dynamic and (type(original_bootstrap) is not bytes or not 2 <= len(original_bootstrap) <= planner.MAX_BYTES):
        execution._fail("activation planning lacks its bounded original root bootstrap")
    endpoint = transport._endpoint(endpoint)
    application, session_scope, target, credential, _count = permission._target
    token = permission._request.cookies.get(application.OIDC_SESSION_COOKIE_NAME)
    if type(token) is not str or len(token) != 64 or any(ord(point) > 127 for point in token):
        execution._fail("activation planning requires the actual pending cookie original")
    old = assertion._token(token.encode("ascii"), work)
    originals = (original_assertion, old, permission._original,
        caller_policy.current_root_enrollment_bytes, caller_policy.grant_enrollment_bytes,
        caller_policy.authorization_enrollment_bytes)
    if not dynamic:
        originals = (original_bootstrap, *originals)
    maximum = caller.grants.replay.MAX_ORIGINAL_BYTES
    if sum(len(raw) for raw in originals) + caller.MAX_AUTHORIZATION_BYTES >= maximum:
        execution._fail("activation planning original inventory exceeds its source bound")
    work.charge(input_bytes=sum(len(raw) for raw in originals))
    # Own all retained graphs together before the first native/key/hash call.
    # Parent configuration alone permits finite floats; proof data does not.
    owned = configured.configuration._ConfigurationCapture(capture._SharedLedger(work),
        maximum_bytes=planner.MAX_BYTES).visit({
            "configuration": parent.configuration_payload,
            "generation": {name: parent.generation[name]
                for name in configured.configuration._GENERATION_FIELDS},
            "runtime": parent.runtime_role_identities, "target": target})
    target = owned["target"]
    subject = {"userId": target["userId"], "sessionId": target["sessionId"],
        "credentialId": target["credentialId"], "credentialRecordId": credential[0],
        "challengeId": challenge_id}
    for name, limit in (("userId", 1024), ("sessionId", 128), ("credentialId", 1366),
            ("credentialRecordId", 1024), ("challengeId", 1024)):
        registration._text(subject[name], name, limit, work)
    if challenge_id == target["challengeId"]:
        execution._fail("activation requires a distinct session-binding challenge, not registration")
    work.charge(input_bytes=sum(4 * len(value) for value in subject.values()))
    request_originals = transport._originals((transport.OPERATION, original_assertion, old,
        *(subject[name].encode("utf-8") for name in (
            "userId", "sessionId", "credentialId", "credentialRecordId", "challengeId"))), response=False)
    window = caller.window_policy._narrow(scope.window,
        deadline_epoch_ns=permission._session_expiry,
        maximum_lifetime_ns=scope.window[5], maximum_clock_skew_ns=scope.window[6])
    bound = min(scope.deadline_ns, window[4])
    if dynamic:
        from serverware import control_plane_oidc_session_activation_request_issuance as request_issuance
        original_bootstrap, window, bound = request_issuance._prepare_on_permission(permission,
            planner_originals=request_originals, live_window=window, deadline_ns=bound)
        work.charge(input_bytes=len(original_bootstrap))
        originals = (original_bootstrap, *originals)
        if sum(map(len, originals)) + caller.MAX_AUTHORIZATION_BYTES >= maximum:
            execution._fail("request-issued planner exceeds the original aggregate inventory")
    material = None
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        if (owner._material is not parent or owner._binding is not binding
                or owner._custody is not custody_owner or parent.activation_planning is not policy
                or parent.activation_execution is not caller_policy
                or not dynamic and policy.planner_bootstrap_bytes is not original_bootstrap
                or policy.planner_endpoint != endpoint):
            execution._fail("activation planning changed its original cold configuration")
        if dynamic:
            from serverware import control_plane_oidc_session_activation_request_issuance as request_issuance
            continuation = permission._request_issuance
            if (type(continuation) is not request_issuance._Continuation
                    or request_issuance._Continuation._check(continuation, permission)[3] is not original_bootstrap):
                execution._fail("activation planning changed its actual issued original")
        permission._narrow_planning(window, bound)
        last_epoch, last_monotonic = permission._continuity(last_epoch, last_monotonic)
        if material is not None:
            sample = planner._fresh(material.attestation_interval, work, opening=material.opening_sample)
            if sample[0] < last_monotonic or sample[1] < last_epoch:
                execution._fail("activation planner launch clock reversed")
            last_epoch, last_monotonic = permission._continuity(sample[1], sample[2])
        if last_epoch >= window[3] or last_monotonic >= bound:
            execution._fail("activation planning original allowance expired")
        return last_epoch

    current()
    material = planner._verify_on_work(bootstrap_bytes=original_bootstrap,
        root_public_key=binding.runtime_root_public_key, live_window=window,
        transport_deadline_ns=bound, work=work)
    if type(material) is not planner._PlannerMaterial:
        execution._fail("activation planner returned no actual original admission")
    window = caller.window_policy._narrow(window,
        deadline_epoch_ns=min(material.attestation_interval[1], window[0] + endpoint[1] * 1_000_000_000),
        maximum_lifetime_ns=material.maximum_plan_age_ns,
        maximum_clock_skew_ns=material.maximum_clock_skew_ns)
    bound = min(bound, window[4])
    current()
    for actual, expected, label in (
            (material.configuration_payload, owned["configuration"], "configuration"),
            (material.generation, owned["generation"], "generation"),
            (material.runtime_role_identities, owned["runtime"], "runtime cohort")):
        configured._same_configuration(actual, expected, work,
            "activation planner differs from the actual parent " + label)
    plan._same(material.configuration_digest, parent.configuration_digest, work,
        "activation planner parent configuration")
    plan._same(material.planner_spki_digest,
        caller.keys._spki_on_work(caller_policy.planner_public_key, work), work,
        "activation planner independently enrolled public key")
    work.charge(input_bytes=len(material.state_enrollment_bytes)
        + len(caller_policy.current_root_enrollment_bytes))
    if (material.state_enrollment_bytes != caller_policy.current_root_enrollment_bytes
            or endpoint[1] > material.launch["requestTimeoutSeconds"]):
        execution._fail("activation planner state original or root timeout differs")
    before = material.complete_root_vector_bytes
    expected_scope = {**subject, "rpId": material.rp_id, "origin": material.origin,
        "authenticationPolicy": material.authn_policy, "trustPolicy": material.trust_policy,
        "configurationDigest": material.configuration_digest, "plannerIdentity": material.planner_identity,
        "plannerSpkiDigest": material.planner_spki_digest,
        "maximumPlanAgeNs": material.maximum_plan_age_ns,
        "maximumClockSkewNs": material.maximum_clock_skew_ns, "deadlineEpochNs": window[3]}
    expected_scope = assertion._Capture(capture._SharedLedger(work),
        maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit(expected_scope)
    current()
    session, _identity, actual_session_scope = production._callback(work,
        lambda: pending._session(application, permission._request))
    if actual_session_scope != session_scope:
        execution._fail("activation pending session changed before planner dispatch")
    old_digest = assertion._digest(old, work)
    plan._same(old_digest, session["token_digest"], work, "activation actual pending cookie")
    assertion_digest = assertion._digest(original_assertion, work)
    work.prepare_encoding(target)
    work.charge(hashes=1)
    current()
    request_binding_digest = production._callback(work,
        lambda: application._control_plane_payload_digest(target))
    current()
    retained_bytes = (sum(len(raw) for raw in originals) + len(before)
        + sum(len(raw) for raw in request_originals) + caller.MAX_AUTHORIZATION_BYTES
        + transport.BOUNDED_REQUEST_HEADER_BYTES + transport.BOUNDED_RESPONSE_HEADER_BYTES
        + transport.MAX_DEADLINE_EPOCH_BYTES)
    response_cap = min(transport.MAX_BOUNDED_RESPONSE_BYTES, maximum - retained_bytes)
    if response_cap < 1:
        execution._fail("activation planner has no bounded original response capacity")
    work.charge(input_bytes=attempts.MAX_CLAIM_IO_BYTES)
    current()
    production._callback(work, lambda: execution.custody.ControlPlaneCustodyClient.claim_oidc_session_activation_dispatch(
            custody_owner,
            finalization_digest=target["localDigest"], request_binding_digest=request_binding_digest,
            authorization_enrollment_digest=caller_policy.authorization_enrollment_digest,
            source_revision=caller.grants.authority.SOURCE_REVISION))
    current()
    # This helper charges native I/O itself; it cannot be placed inside a
    # metrics-constant callback. Uncertainty, EOF and normal-close errors fail.
    response = transport._socket_request_bounded(endpoint, originals=request_originals,
        deadline_epoch_ns=window[3], deadline_ns=bound, work=work, current=current,
        maximum_response_bytes=response_cap)
    current()
    response = transport._originals(response, response=True)
    if response[0] != b"prepared" or retained_bytes + sum(len(raw) for raw in response) > maximum:
        execution._fail("activation planner returned uncertainty or oversized originals; no retry")
    request = _object(response[1], caller.grants.authority.MAX_REQUEST_BYTES, work)
    returned_scope = _object(response[2], assertion.MAX_CONTEXT_BYTES, work)
    registration._closed(returned_scope, caller.expectations_wire.plan._SCOPE_FIELDS,
        "activation planner returned scope")
    returned_deadline = registration._integer(returned_scope["deadlineEpochNs"],
        "activation planner returned deadline", 1)
    if returned_deadline > window[3] or current() >= returned_deadline:
        execution._fail("activation planner returned an expired or widened deadline")
    expected_scope["deadlineEpochNs"] = returned_deadline
    plan._same(returned_scope, expected_scope, work, "independently held activation planning scope")
    window = caller.window_policy._narrow(window, deadline_epoch_ns=returned_deadline,
        maximum_lifetime_ns=window[5], maximum_clock_skew_ns=window[6])
    bound = min(bound, window[4])
    current()
    expectations = caller.expectations_wire._capture_on_work({"request": request,
        "scope": expected_scope, "journalDigest": response[5].decode("ascii")}, work=work)
    arguments = caller.expectations_wire.plan.transition._arguments(expectations["request"]["arguments"], work)
    for field, expected in (("user_id", subject["userId"]), ("session_id", subject["sessionId"]),
            ("credential_id", subject["credentialId"]), ("credential_record_id", subject["credentialRecordId"]),
            ("challenge_id", challenge_id), ("old_token_digest", old_digest),
            ("assertion_digest", assertion_digest), ("delivery_ttl_seconds", material.delivery_ttl_seconds)):
        plan._same(arguments[field], expected, work, "activation planner exact original " + field)
    actual_plan, digest = caller.activation._authenticate(response[3], expectations["request"],
        expected_scope, caller_policy.planner_public_key, current, work)
    plan._same(digest, response[4].decode("ascii"), work, "activation original plan locator")
    if actual_plan["issuedAtEpochNs"] < permission._permission_epoch:
        execution._fail("activation planner signed before this permission and counter update")
    window = caller.window_policy._narrow(window, deadline_epoch_ns=actual_plan["expiresAtEpochNs"],
        maximum_lifetime_ns=window[5], maximum_clock_skew_ns=window[6])
    bound = min(bound, window[4])
    current()
    raw2 = response[3], response[6]
    authorization = permission.authorize(originals=raw2, expectations=expectations, before_vector_bytes=before)
    current()
    # Ordinary originals/data only. A later consumer must authenticate these
    # originals itself; no grant, commit, delivery or session claim is returned.
    return raw2, expectations, before, authorization
