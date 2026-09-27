"""Private authenticated-app continuation to genuinely verified evidence.

The actual operator/OIDC handler must already have admitted its caller and the
original enrollment ceremony. An original-input carrier is not authentication,
row membership or a reservation. This continuation observes only a publication
selector, obtains the real source exchange and issues one grant for one signer
exchange. It neither retries nor falls back to legacy finalization.

Only the two existing cold owners supply runtime/configuration/key/endpoint
authority. One standard work allowance and one original live window cover this
composition. No caller-selected time, work, root, endpoint or session override
is accepted. Separate entrypoints prepare evidence, durably retain prepared
custody, or explicitly append then forward once. None returns registration
success: current roots, complete OIDC sibling/history and atomic business
execution remain separate prerequisites. The separate finalization preparation
entrypoint consumes retained signer originals, derives sibling selectors only
after genuine replay, and durably retains prepared raw7 without signing anew.
"""
from __future__ import annotations

from datetime import datetime, timezone


class RegistrationPreparationError(ValueError):
    pass


def prepare_registration_evidence(originals):
    """Return actual (evidence envelope, evidence-admit request, input bytes)."""
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    exchange, _custody, _window = _prepare_registration_exchange_on_work(
        originals, _ValidationWork(QueryReadValidationLimits()))
    return exchange[1][0], exchange[2], exchange[3]


def _prepare_registration_exchange_on_work(originals, work):
    """Same real composition, preserving raw8/raw2 for independent replay."""
    from serverware import control_plane_custody_client as custody_client
    from serverware import control_plane_custody_startup as custody_startup
    from serverware import control_plane_enrollment_startup as enrollment_startup
    from serverware import authority_webauthn_enrollment_issuer as issuer
    from serverware import db, webauthn
    ledger = issuer.evidence.capture._SharedLedger(work)
    if type(originals) is not webauthn._RegistrationOriginals:
        raise RegistrationPreparationError("registration preparation requires actual original inputs")
    scope = originals.scope
    if type(scope) is not issuer.production.attestation.CeremonyScope:
        raise RegistrationPreparationError("registration preparation requires the original ceremony scope")
    client_bytes, attestation_bytes, transports = issuer.authorization._originals(
        originals.client_data_json, originals.attestation_object, originals.transports)
    authorization_bytes = scope.authorization_json
    if (type(authorization_bytes) is not bytes
            or not 2 <= len(authorization_bytes) <= issuer.authorization.MAX_BYTES):
        raise RegistrationPreparationError("original enrollment authorization exceeds its source bound")
    work.prepare_copy(transports)
    held = issuer.authorization._capture({"credentialId": originals.credential_id,
        "transports": list(transports), "challengeId": scope.challenge_id,
        "challenge": scope.challenge, "userId": scope.user_id, "label": scope.label,
        "rpId": originals.rp_id, "origin": originals.origin}, work)
    work.prepare_copy(held["transports"])
    held_transports = tuple(held["transports"])

    # All browser/scope references are held before cold-owner continuity makes
    # any actual descriptor, clock or key callback. Development opt-out cannot
    # turn this private evidence path into legacy registration authority.
    callback = issuer.evidence.production._callback
    custody = callback(work, custody_startup.require_started)
    enrollment = callback(work, enrollment_startup.require_started)
    if (type(custody) is not custody_client.ControlPlaneCustodyClient
            or type(enrollment) is not enrollment_startup._EnrollmentOwner):
        raise RegistrationPreparationError("registration preparation requires both enabled cold owners")
    binding = callback(work, lambda: custody_client._snapshot(custody))
    material = enrollment._material
    if (material is None or enrollment._private_key is None
            or material.issuer_policy is None or material.signer_endpoint is None
            or enrollment._custody is not custody or enrollment._binding is not binding
            or material.configuration_digest != binding.configuration_digest):
        raise RegistrationPreparationError("registration cold owners do not share the admitted configuration")
    endpoint = material.signer_endpoint
    receipt_expiry = binding.attestation_interval[1]
    maximum_lifetime = min(binding.maximum_deadline_ns,
        int(endpoint[1] * 1_000_000_000), issuer.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    skew = material.issuer_policy["maximumClockSkewNs"]
    clock = issuer.authorization.clock
    window = clock._open_on_work(deadline_epoch_ns=receipt_expiry,
        maximum_lifetime_ns=maximum_lifetime, maximum_clock_skew_ns=skew, work=work)
    deadline, monotonic_deadline = window[3], window[4]

    authorization = issuer.evidence.wire._decode_object(authorization_bytes, work=work,
        maximum_bytes=issuer.authorization.MAX_BYTES,
        maximum_nodes=issuer.authorization.MAX_NODES,
        maximum_depth=issuer.authorization.MAX_DEPTH)
    authorization = issuer.authorization._capture(authorization, work)
    issuer.evidence.capability._canonical(authorization_bytes, authorization, ledger,
        issuer.authorization.MAX_BYTES, issuer.authorization.MAX_NODES)
    mode = authorization.get("mode")
    if type(mode) is not str or mode not in issuer.authorization.registration._MODES:
        raise RegistrationPreparationError("original enrollment mode is not source fixed")
    issuer.evidence.plan.contract._digest(authorization.get("payload_digest"))
    # There is deliberately no parallel session argument. These are the same
    # mode/user/session joins subsequently enforced by the real grant context.
    session_id = None
    if mode == "oidc-session-first-enrollment":
        session_id = authorization.get("session_id")
        issuer.production.attestation._text(session_id, "original OIDC session", 4096, _work=work)
        issuer.evidence.plan._same(authorization.get("user_id"), held["userId"], work,
            "original OIDC enrollment user differs from ceremony scope")
    held_scope = issuer.production.attestation.CeremonyScope(held["challengeId"],
        held["challenge"], held["userId"], held["label"], authorization_bytes, _work=work)
    captured = webauthn._RegistrationOriginals(client_bytes, attestation_bytes,
        held["credentialId"], held_transports, held_scope, held["rpId"], held["origin"])
    clock._check_on_work(window, work=work)

    # This real bounded read supplies a selector only. It cannot establish
    # prior-publication provenance, membership, current roots or reservation.
    publication_id = callback(work, db.observe_published_webauthn_trust_publication_id)
    issuer.production.attestation._text(publication_id, "observed publication ID", 4096, _work=work)
    clock._check_on_work(window, work=work)
    source_originals = custody_client.ControlPlaneCustodyClient.request_registration_source(
        custody, registration_challenge_id=held["challengeId"],
        published_publication_id=publication_id, oidc_session_id=session_id,
        deadline_epoch_ns=deadline, deadline_ns=monotonic_deadline, work=work)
    clock._check_on_work(window, work=work)

    # Sample this actual UTC instant once after source acquisition. Never
    # derive it from a returned cutoff, replace it after failure or renew the
    # window. The genuine consumer still enforces every original-time join.
    verified_at = callback(work, lambda: datetime.now(timezone.utc))
    clock._check_on_work(window, work=work)
    result = enrollment_startup._EnrollmentOwner._request_registration_evidence_exchange(
        enrollment, captured, source_originals=source_originals,
        verified_at=verified_at, deadline_epoch_ns=deadline,
        deadline_ns=monotonic_deadline, work=work)
    clock._check_on_work(window, work=work)
    if (callback(work, custody_startup.require_started) is not custody
            or callback(work, enrollment_startup.require_started) is not enrollment
            or enrollment._material is not material
            or callback(work, lambda: custody_client._snapshot(custody)) is not binding):
        raise RegistrationPreparationError("registration cold owners changed during preparation")
    clock._check_on_work(window, work=work)
    return result, custody, window


def _prepare_registration_custody_on_work(originals, work):
    from serverware import authority_webauthn_enrollment_issuer as issuer
    from serverware import control_plane_custody_client as custody_client
    from serverware import control_plane_custody_startup as custody_startup

    exchange, custody, window = _prepare_registration_exchange_on_work(originals, work)
    # No replay-success carrier crosses the next service boundary. The actual
    # verifier receives every original and reconstructs the invocation itself.
    # These are byte strings, not a JSON graph. The JSON-copy meter rejects
    # bytes; charge their existing raw spans before the bounded tuple join.
    work.charge(input_bytes=sum(len(raw) for raw in exchange[0])
        + sum(len(raw) for raw in exchange[1]))
    raw_ten = exchange[0] + exchange[1]
    clock = issuer.authorization.clock
    clock._check_on_work(window, work=work)
    prepared = custody_client.ControlPlaneCustodyClient.prepare_registration_custody(
        custody, raw_ten, deadline_epoch_ns=window[3], deadline_ns=window[4], work=work)
    clock._check_on_work(window, work=work)
    if issuer.evidence.production._callback(work, custody_startup.require_started) is not custody:
        raise RegistrationPreparationError("registration custody owner changed during preparation")
    clock._check_on_work(window, work=work)
    return custody, prepared, window


def prepare_registration_custody(originals):
    """Durably append real prepared raw6, returning only its local content ID.

    The append can finish after the preparation window; that retains opaque
    evidence, not renewed authority. This function never forwards or retries.
    """
    from serverware import control_plane_custody_client as custody_client
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    custody, prepared, _window = _prepare_registration_custody_on_work(
        originals, _ValidationWork(QueryReadValidationLimits()))
    return custody_client.ControlPlaneCustodyClient.append_evidence(custody, "registration", prepared)


def prepare_and_forward_registration_custody(originals):
    """Append first, then attempt forwarding once under the original deadline.

    The existing typed outcome error retains the local content ID on ordinary
    post-append failure; the journal's attempt marker is never cleared. A peer
    observation is neither remote durability proof nor credential finalization.
    """
    from serverware import control_plane_custody_client as custody_client
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    custody, prepared, window = _prepare_registration_custody_on_work(
        originals, _ValidationWork(QueryReadValidationLimits()))
    return custody_client.ControlPlaneCustodyClient.append_and_forward_evidence(
        custody, "registration", prepared, deadline_ns=window[4])


def prepare_registration_execution_grant(originals):
    """Private authenticated-app action; return original grant-bundle raw10.

    The real operator/OIDC handler must separately admit the present caller and
    new execution-request purpose before this call. Existing public custody-only
    routes do not invoke it. An original-input container is not that permission.
    Order: original caller authorization, planning request3, response4, complete
    before-vector, original verified grant. This neither journals nor forwards
    execution, reserves a current root or reports registration success.
    """
    from serverware import control_plane_custody_client as custody_client
    from serverware import control_plane_custody_startup as custody_startup
    from serverware import control_plane_enrollment_startup as enrollment_startup
    from serverware import authority_webauthn_enrollment_issuer as issuer
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    work = _ValidationWork(QueryReadValidationLimits())
    callback = issuer.evidence.production._callback
    enrollment = callback(work, enrollment_startup.require_started)
    if (type(enrollment) is not enrollment_startup._EnrollmentOwner
            or not callback(work, lambda: enrollment.execution_enabled)):
        raise RegistrationPreparationError("registration execution purpose is not cold-enabled")
    material = enrollment._material
    exchange, custody, window = _prepare_registration_exchange_on_work(originals, work)
    clock = issuer.authorization.clock
    clock._check_on_work(window, work=work)
    authorization = enrollment_startup._EnrollmentOwner._authorize_registration_execution(
        enrollment, request_originals=exchange[0], response_originals=exchange[1],
        deadline_epoch_ns=window[3], deadline_ns=window[4], work=work)
    work.charge(input_bytes=sum(len(raw) for raw in exchange[0])
        + sum(len(raw) for raw in exchange[1]))
    planning = custody_client.ControlPlaneCustodyClient.prepare_registration_execution_plan(
        custody, exchange[0] + exchange[1], deadline_epoch_ns=window[3], deadline_ns=window[4], work=work)
    clock._check_on_work(window, work=work)
    grant = enrollment_startup._EnrollmentOwner._request_registration_execution_grant(
        enrollment, authorization_bytes=authorization, request_originals=planning[:3],
        response_originals=planning[3:7], before_vector_bytes=planning[7],
        deadline_epoch_ns=window[3], deadline_ns=window[4], work=work)
    if (callback(work, enrollment_startup.require_started) is not enrollment
            or enrollment._material is not material
            or callback(work, custody_startup.require_started) is not custody):
        raise RegistrationPreparationError("registration execution cold owner changed")
    clock._check_on_work(window, work=work)
    total = len(authorization) + sum(len(raw) for raw in planning) + len(grant)
    if total > issuer.authority.MAX_RESULT_BYTES:
        raise RegistrationPreparationError("registration execution originals exceed the source aggregate")
    work.charge(input_bytes=total)
    return (authorization, *planning, grant)


def prepare_registration_finalization(*, request_originals, response_originals):
    """Replay retained signer originals, observe hints, prepare and retain raw7.

    The actual authenticated application must own this original exchange and
    complete its separate evidence business admission first. Re-running the
    signer here would change the evidence identity, so no grant/signing helper
    is called. This returns only the local prepared-record digest, never a
    credential, active session, remote receipt or permission to execute.
    """
    from serverware import authority_webauthn_enrollment_issuer as issuer
    from serverware import authority_webauthn_registration_custody_caller as raw
    from serverware import authority_webauthn_registration_signer_response as verifying
    from serverware import control_plane_custody_client as custody_client
    from serverware import control_plane_custody_startup as custody_startup
    from serverware import control_plane_enrollment_startup as enrollment_startup
    from serverware import db
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    work = _ValidationWork(QueryReadValidationLimits())
    ledger = issuer.evidence.capture._SharedLedger(work)
    request = verifying.wire._request_originals(request_originals)
    response = verifying.wire._response_originals(response_originals)
    work.charge(input_bytes=sum(len(value) for value in request)
        + sum(len(value) for value in response))
    originals = raw._request_originals(request + response)
    callback = issuer.evidence.production._callback
    custody = callback(work, custody_startup.require_started)
    enrollment = callback(work, enrollment_startup.require_started)
    if (type(custody) is not custody_client.ControlPlaneCustodyClient
            or type(enrollment) is not enrollment_startup._EnrollmentOwner):
        raise RegistrationPreparationError("registration finalization requires both actual cold owners")
    binding = callback(work, lambda: custody_client._snapshot(custody))
    material = enrollment._material
    if (material is None or material.issuer_policy is None
            or enrollment._custody is not custody or enrollment._binding is not binding
            or material.configuration_digest != binding.configuration_digest):
        raise RegistrationPreparationError("registration finalization cold configurations differ")
    digest = material.configuration_digest
    payload = issuer.configuration._ConfigurationCapture(ledger,
        maximum_bytes=issuer.authority.MAX_REQUEST_BYTES).visit(material.configuration_payload)
    generation = issuer.evidence.capture._JSONCapture(ledger).visit(material.generation)
    runtime = issuer.evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(material.runtime_role_identities)
    skew = material.issuer_policy["maximumClockSkewNs"]
    clock = issuer.authorization.clock
    window = clock._open_on_work(deadline_epoch_ns=binding.attestation_interval[1],
        maximum_lifetime_ns=min(binding.maximum_deadline_ns,
            issuer.authority.VERIFIER_RESPONSE_MAX_AGE_NS),
        maximum_clock_skew_ns=skew, work=work)
    last_epoch = window[0]

    def current():
        nonlocal last_epoch
        if (enrollment._material is not material or enrollment._binding is not binding
                or callback(work, custody_startup.require_started) is not custody
                or callback(work, enrollment_startup.require_started) is not enrollment
                or callback(work, lambda: custody_client._snapshot(custody)) is not binding):
            raise RegistrationPreparationError("registration finalization cold owners changed")
        now = clock._check_on_work(window, work=work)
        if now < last_epoch:
            raise RegistrationPreparationError("registration finalization clock reversed")
        last_epoch = now
        callback(work, lambda: raw._check_deadline(window[4]))

    current()
    # Empty hints are used only to derive selectors from genuine original
    # grant/source/attestation/evidence replay. This is NOT complete population
    # admission, and this temporary request never reaches a planner or writer.
    derived, _inputs = verifying._verify_finalization_on_configuration(payload=payload,
        configuration_digest=digest, generation=generation, runtime_role_identities=runtime,
        request_originals=request, response_originals=response,
        sibling_challenge_ids=[], work=work)
    current()
    arguments = derived["arguments"]
    intent = arguments["semantic_intent"]
    user_id, challenge_id, session_id = intent["userId"], intent["challengeId"], arguments["oidc_session_id"]
    siblings = []
    if session_id is not None:
        siblings = callback(work, lambda: db.observe_webauthn_registration_sibling_challenge_ids(
            user_id=user_id, registration_challenge_id=challenge_id))
    current()
    # Send originals, not the temporary derived request. The actual verifier
    # repeats genuine replay and proves complete history/siblings plus the
    # unconsumed v2 evidence row at its own actual planning cutoff.
    prepared = custody_client.ControlPlaneCustodyClient.prepare_registration_finalization(
        custody, originals, sibling_challenge_ids=siblings,
        deadline_epoch_ns=window[3], deadline_ns=window[4], work=work)
    current()
    # As with evidence preparation, a late append retains opaque originals;
    # it grants no lifetime renewal. No remote writer is contacted here.
    return custody_client.ControlPlaneCustodyClient.append_transition(
        custody, verifying.production.registration.OPERATION, prepared)
