"""Cold finalization caller and authorization-before-new-plan continuation.

The actual application must separately admit the present finalization execution
purpose. The retained facade additionally replays ownership and acknowledged
evidence completion before entering this module. Neither those originals nor
the old preparation-only route provide that new permission.

The root-admitted finalization profile owns a distinct signing descriptor and
enrollment. Authorization is issued from genuine signer replay at a current
sample BEFORE one new planner request. The returned authorization/raw7 are
genuinely joined locally; an older plan is not accepted or retimed. This private
planning continuation does not journal, request a grant, reserve, execute SQL
or activate a session. A separate explicit grant-preparation method acquires
the complete vector with the new plan, requests and verifies the actual grant.
A separate explicit grant-request method authenticates
raw8, exchanges once at its independently configured endpoint, and verifies the
returned original grant against the full vector. The public grant-preparation
facade invokes the complete new-plan/vector/grant path under separate present
permission and retains the exact resulting originals. The private raw8-only
planning continuation remains unexposed.

An explicit nested-v2 reserve continuation authenticates complete original
raw10 before one transport and verifies returned raw3 against independently
root-admitted predecessor pins. It does not store originals, execute SQL or
infer latest state from the acknowledgment.
"""
from __future__ import annotations

import time

from catchplate import authority_registration_finalization_authorization as authorization
from catchplate import authority_registration_finalization_issuance as issuance
from catchplate import authority_registration_finalization_plan_admission as admission
from catchplate import authority_webauthn_registration_signer_response as signer_response
from catchplate import control_plane_custody_client as custody_client
from catchplate import control_plane_custody_startup as custody_startup
from catchplate import control_plane_enrollment_startup as startup


evidence, clock, shape = admission.evidence, authorization.clock, authorization.shape


def _scope(owner, *, live_window, work, transport_deadline_ns=None):
    """Retain actual cold authority under the caller's unchanged clock bracket."""
    startup._require_pid()
    if type(owner) is not startup._EnrollmentOwner:
        raise startup.EnrollmentStartupError("finalization requires the actual cold enrollment owner")
    material, binding, private = owner._material, owner._binding, owner._finalization_key
    if material is None or material.finalization is None or private is None:
        raise startup.EnrollmentStartupError("dedicated finalization caller permission is disabled")
    finalization, custody = material.finalization, owner._custody
    if (material.issuer_policy is None or owner._private_key is None
            or owner._finalization_key_fd != finalization.caller_private_key_fd
            or material.configuration_digest != binding.configuration_digest
            or binding.caller_uid != 65532
            or type(custody) is not custody_client.ControlPlaneCustodyClient):
        raise startup.EnrollmentStartupError("finalization caller cold scope differs")
    window = clock._validate(live_window)
    if (window[3] > binding.attestation_interval[1]
            or window[5] > binding.maximum_deadline_ns
            or window[6] > material.issuer_policy["maximumClockSkewNs"]):
        raise startup.EnrollmentStartupError("finalization caller widens the original processing scope")
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    bound = window[4] if transport_deadline_ns is None else min(window[4], transport_deadline_ns)
    ledger = evidence.capture._SharedLedger(work)
    configuration = admission.custody.configuration.configuration
    common = {
        "payload": configuration._ConfigurationCapture(ledger,
            maximum_bytes=evidence.authority.MAX_REQUEST_BYTES).visit(material.configuration_payload),
        "configuration_digest": material.configuration_digest,
        "generation": evidence.capture._JSONCapture(ledger).visit(material.generation),
        "runtime_role_identities": evidence.capture._JSONCapture(ledger,
            maximum_bytes=8192).visit(material.runtime_role_identities),
        "authorization_enrollment_bytes": finalization.authorization_enrollment_bytes,
        "current_root_enrollment_bytes": finalization.current_root_enrollment_bytes,
        "grant_enrollment_bytes": finalization.grant_enrollment_bytes,
        "root_public_key": binding.runtime_root_public_key,
    }
    last_epoch, last_monotonic = window[0], window[2]
    callback = evidence.production._callback

    def current():
        nonlocal last_epoch, last_monotonic
        startup._live(owner, work=work)
        if (owner._material is not material or owner._binding is not binding
                or owner._finalization_key is not private or material.finalization is not finalization
                or owner._custody is not custody
                or callback(work, startup.require_started) is not owner
                or callback(work, custody_startup.require_started) is not custody
                or callback(work, lambda: custody_client._snapshot(custody)) is not binding):
            raise startup.EnrollmentStartupError("finalization caller changed during the operation")
        now = clock._check_on_work(window, work=work)
        monotonic = callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise startup.EnrollmentStartupError("finalization caller expired or clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    current()
    return common, private, window, bound, current


def _authorize_on_owner(owner, *, request_originals, response_originals,
        sibling_challenge_ids, live_window, work, transport_deadline_ns=None):
    """Sign only the exact replayed finalization request, never a posted digest."""
    request = signer_response.wire._request_originals(request_originals)
    response = signer_response.wire._response_originals(response_originals)
    siblings = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work),
        maximum_bytes=evidence.authority.MAX_REQUEST_BYTES).visit(sibling_challenge_ids)
    common, private, window, bound, current = _scope(owner, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    original = issuance._produce_on_configuration(**common, request_originals=request,
        response_originals=response, sibling_challenge_ids=siblings, caller_private_key=private,
        live_window=window, transport_deadline_ns=bound, work=work)
    current()
    return original


def _prepare_on_owner(owner, *, signer_originals, live_window, work,
        transport_deadline_ns=None, retained_original_bytes=0, _with_vector=False):
    """Authorize first, request one new plan, then admit the original raw8.

    Called after genuine retained ownership/completion replay on the same work
    and owner lock. The optional inventory count only narrows the aggregate
    byte allowance; it is not scope, provenance or permission.
    """
    from catchplate import authority_webauthn_registration_custody_caller as signer_wire
    from catchplate import authority_webauthn_registration_finalization_caller as plan_wire
    from catchplate import db

    raw = signer_wire._request_originals(signer_originals)
    if type(_with_vector) is not bool:
        raise startup.EnrollmentStartupError("finalization planning profile is not source-selected")
    if _with_vector:
        from catchplate import authority_webauthn_registration_finalization_execution_caller as plan_wire
    shape._integer(retained_original_bytes, evidence.authority.MAX_RESULT_BYTES)
    common, _private, window, bound, current = _scope(owner, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    retained = max(retained_original_bytes, sum(len(value) for value in raw))
    enrollment_bytes = sum(len(common[name]) for name in (
        "authorization_enrollment_bytes", "current_root_enrollment_bytes", "grant_enrollment_bytes"))
    if retained + enrollment_bytes > evidence.authority.MAX_RESULT_BYTES:
        raise startup.EnrollmentStartupError("finalization preparation originals exceed their aggregate bound")
    callback = evidence.production._callback
    config = {name: common[name] for name in (
        "payload", "configuration_digest", "generation", "runtime_role_identities")}
    # Empty hints derive selectors only. The final signed request is replayed
    # again using the exact observed hint set before authorization, and the
    # measured planner independently proves the complete sibling population.
    derived, _inputs = signer_response._verify_finalization_on_configuration(**config,
        request_originals=raw[:8], response_originals=raw[8:], sibling_challenge_ids=[], work=work)
    current()
    arguments = derived["arguments"]
    intent = arguments["semantic_intent"]
    user_id, challenge_id = intent["userId"], intent["challengeId"]
    siblings = []
    if arguments["oidc_session_id"] is not None:
        siblings = callback(work, lambda: db.observe_webauthn_registration_sibling_challenge_ids(
            user_id=user_id, registration_challenge_id=challenge_id))
    siblings = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work),
        maximum_bytes=plan_wire.MAX_HINTS_BYTES).visit(siblings)
    current()
    original_authorization = startup._EnrollmentOwner._authorize_registration_finalization(
        owner, request_originals=raw[:8], response_originals=raw[8:], sibling_challenge_ids=siblings,
        live_window=window, transport_deadline_ns=bound, work=work)
    current()
    configured = admission.custody.configuration._capture_on_work(operation=authorization.OPERATION,
        **config, work=work)
    authorized = authorization._verify_on_work(authorization_bytes=original_authorization,
        authorization_enrollment_bytes=common["authorization_enrollment_bytes"],
        current_root_enrollment_bytes=common["current_root_enrollment_bytes"],
        grant_enrollment_bytes=common["grant_enrollment_bytes"], root_public_key=common["root_public_key"],
        configuration_digest=common["configuration_digest"], planner_public_key=configured.pins[1],
        evidence_public_key=configured.pins[4], live_window=window,
        transport_deadline_ns=bound, work=work)
    deadline = min(window[3], authorized.expires_at_epoch_ns)
    bound = min(bound, window[1] + deadline - window[0])
    last_epoch, last_monotonic = authorized.last_epoch_ns, authorized.last_monotonic_ns

    def authorized_current():
        nonlocal last_epoch, last_monotonic
        now = current()
        monotonic = callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if (now < last_epoch or monotonic < last_monotonic or monotonic >= bound
                or now >= deadline or authorized.issued_at_epoch_ns > now + authorized.maximum_clock_skew_ns
                or now - authorized.issued_at_epoch_ns > authorized.maximum_age_ns):
            raise startup.EnrollmentStartupError("finalization authorization expired or clocks reversed")
        last_epoch, last_monotonic = now, monotonic

    authorized_current()
    if retained + enrollment_bytes + len(original_authorization) > evidence.authority.MAX_RESULT_BYTES:
        raise startup.EnrollmentStartupError("finalization authorization exceeds the original aggregate bound")
    # This is deliberately AFTER actual authorization issuance and verification.
    # A previous raw7 is not an input. No callback can retime or replace the
    # caller's original window, siblings, grant originals or authorization.
    prepare = (custody_client.ControlPlaneCustodyClient.prepare_registration_finalization_execution
        if _with_vector else custody_client.ControlPlaneCustodyClient.prepare_registration_finalization)
    prepared = prepare(
        owner._custody, raw, sibling_challenge_ids=siblings,
        deadline_epoch_ns=deadline, deadline_ns=bound, work=work)
    prepared = plan_wire._response_originals(prepared)
    if (retained + enrollment_bytes + len(original_authorization)
            + sum(len(value) for value in prepared) > evidence.authority.MAX_RESULT_BYTES):
        raise startup.EnrollmentStartupError("finalization plan exceeds the original aggregate bound")
    authorized_current()
    admitted = admission._verify_on_configuration(**common, originals=prepared[:7],
        authorization_bytes=original_authorization, live_window=window,
        transport_deadline_ns=bound, work=work)
    authorized_current()
    return (original_authorization, *admitted, *prepared[7:])


def _prepare_grant_on_owner(owner, *, signer_originals, live_window, work,
        transport_deadline_ns=None, retained_original_bytes=0):
    """Explicit authorized new-plan/vector/grant composition; no storage or SQL."""
    originals = _prepare_on_owner(owner, signer_originals=signer_originals,
        live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns,
        retained_original_bytes=retained_original_bytes, _with_vector=True)
    grant = startup._EnrollmentOwner._request_registration_finalization_grant(owner,
        originals=originals[:8], before_vector_bytes=originals[8], live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    finalization = owner._material.finalization
    enrollment_bytes = sum(len(raw) for raw in (finalization.authorization_enrollment_bytes,
        finalization.current_root_enrollment_bytes, finalization.grant_enrollment_bytes))
    if (retained_original_bytes + enrollment_bytes + sum(len(raw) for raw in originals)
            + len(grant) > evidence.authority.MAX_RESULT_BYTES):
        raise startup.EnrollmentStartupError("finalization grant preparation exceeds its original aggregate bound")
    return (*originals, grant)


def _request_on_owner(owner, *, originals, before_vector_bytes, live_window,
        work, transport_deadline_ns=None):
    """Explicit original grant exchange, never automatic after preparation.

    The caller supplies original raw8 and the genuinely acquired complete
    before-vector. Neither a prior admission result nor an old preparation-only
    raw7 can replace the original dedicated authorization. The cold service is
    an independently admitted peer; no fallback to the evidence authorizer exists.
    """
    from catchplate import authority_registration_finalization_transport as transport
    from catchplate import authority_registration_finalization_execution_admission as receiving

    if type(originals) is not tuple or len(originals) != 8:
        raise startup.EnrollmentStartupError("finalization grant requires original authorization plus raw7")
    held = transport._originals((*originals, before_vector_bytes), transport.REQUEST_LIMITS)
    common, _private, window, bound, current = _scope(owner, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    endpoint = owner._material.finalization.authorizer_endpoint
    # A configured per-request cap starts at the ORIGINAL opening bracket,
    # never at the end of expensive replay or after a failed socket operation.
    bound = min(bound, window[1] + int(endpoint[1] * 1_000_000_000))
    inventory_bytes = sum(len(raw) for raw in held) + sum(len(common[name]) for name in (
        "authorization_enrollment_bytes", "current_root_enrollment_bytes", "grant_enrollment_bytes"))
    if inventory_bytes > evidence.authority.MAX_RESULT_BYTES:
        raise startup.EnrollmentStartupError("finalization grant exchange exceeds its original aggregate bound")
    admitted = admission._admit_on_configuration(**common, originals=held[1:8],
        authorization_bytes=held[0], live_window=window,
        transport_deadline_ns=bound, work=work)
    bound = min(bound, admitted.deadline_ns)
    current()
    admitted.check()
    callback = evidence.production._callback
    returned = callback(work,
        lambda: transport._socket_request(endpoint, originals=held, deadline_ns=bound))
    current()
    admitted.check()
    original_grant = authorization.authorization._original(returned,
        authorization.grants.MAX_GRANT_BYTES, "returned finalization execution grant")
    if inventory_bytes + len(original_grant) > evidence.authority.MAX_RESULT_BYTES:
        raise startup.EnrollmentStartupError("returned finalization grant exceeds the original aggregate bound")
    receiving._verify_on_configuration(**common, originals=held[1:8], before_vector_bytes=held[8],
        authorization_bytes=held[0], grant_bytes=original_grant, live_window=window,
        transport_deadline_ns=bound, work=work)
    current()
    admitted.check()
    callback(work, lambda: transport._check_deadline(bound))
    return original_grant


def _reserve_on_owner(owner, *, originals, live_window, transport_deadline_ns, work):
    """Admit original raw10, exchange once, and return genuinely verified raw3.

    Present caller/new-purpose admission precedes this private entrypoint.
    No current scope is adopted from a returned receipt, and no failure grants
    retry permission after the possible remote reserve side effect.
    """
    from catchplate import authority_registration_finalization_execution_admission as receiving
    from catchplate import authority_registration_finalization_reservation_response as response
    from catchplate import authority_registration_finalization_reservation_transport as transport

    held = transport._originals(originals, response=False)
    shape._integer(transport_deadline_ns, minimum=1)
    common, _private, window, bound, current = _scope(owner, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    finalization = owner._material.finalization
    if finalization.reservation_endpoint is None or (finalization.reservation_predecessor is None
            and finalization.context_directory is None):
        raise startup.EnrollmentStartupError("dedicated finalization reservation permission is disabled")
    endpoint = transport._endpoint(finalization.reservation_endpoint)
    predecessor = finalization.reservation_predecessor
    if finalization.context_directory is not None:
        from catchplate import authority_local_registration_context as contexts
        from catchplate import control_plane_registration_finalization_reservation as subjects
        digest = contexts._record("finalization", held)
        subject, stored, window, bound, subject_live, _ = subjects._inspect_on_owner(owner, digest,
            live_window=window, transport_deadline_ns=bound, work=work)
        if stored != held:
            raise startup.EnrollmentStartupError("local context differs from actual retained finalization")
        selected = contexts._admit_on_owner(owner, purpose="finalization", local_digest=digest, stage="reserve",
            common=common, originals=held, reserved=None, subject=subject,
            deadline_epoch_ns=window[3], deadline_ns=bound, work=work)
        predecessor = tuple(selected["scope"][name] for name in ("sequence", "headDigest", "nextFence"))
        window, bound = contexts._narrow(selected, window, bound)
        subject_live()
    sequence, head, fence = response.records._predecessor_scope(*predecessor)
    # The per-request endpoint cap starts at the original opening bracket,
    # not after admission and never after a previous send attempt.
    bound = min(bound, window[1] + endpoint[1] * 1_000_000_000)
    inventory_bytes = sum(len(raw) for raw in held) + sum(len(common[name]) for name in (
        "authorization_enrollment_bytes", "current_root_enrollment_bytes", "grant_enrollment_bytes"))
    if inventory_bytes > evidence.authority.MAX_RESULT_BYTES:
        raise startup.EnrollmentStartupError("finalization reserve exceeds its original aggregate bound")
    admitted = receiving._admit_on_configuration(**common, originals=held[1:8],
        before_vector_bytes=held[8], authorization_bytes=held[0], grant_bytes=held[9],
        live_window=window, transport_deadline_ns=bound, work=work)
    bound = min(bound, admitted.deadline_ns)
    current()
    admitted.live()
    callback = evidence.production._callback
    callback(work, lambda: transport._check_deadline(bound))
    if finalization.context_directory is not None:
        contexts._claim_reservation_on_owner(owner, "finalization", digest)
    returned = callback(work,
        lambda: transport._socket_request(endpoint, originals=held, deadline_ns=bound))
    current()
    admitted.live()
    returned = transport._originals(returned, response=True)
    if inventory_bytes + sum(len(raw) for raw in returned) > evidence.authority.MAX_RESULT_BYTES:
        raise startup.EnrollmentStartupError("returned finalization reserve exceeds the original aggregate bound")
    verified = response._verify_on_configuration(**common, originals=held,
        response_originals=returned, expected_predecessor_sequence=sequence,
        expected_predecessor_head_digest=head, expected_fence=fence,
        live_window=admitted.window, transport_deadline_ns=bound, work=work)
    current()
    admitted.live()
    callback(work, lambda: transport._check_deadline(bound))
    return verified
