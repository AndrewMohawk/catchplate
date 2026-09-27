"""Historical original registration signer replay, never live permission.

The caller independently supplies current root-admitted configuration, its
generation/runtime cohort, original request8/response2, and one already-opened
current work/window. This separate verifier authenticates the old enrollment,
source controls and evidence signatures, replays original source proofs and
WebAuthn ceremony/attestation semantics, and regenerates the exact evidence
admission request. Past expiry is historical data, not renewed signing or SQL
authority. Existing live signers/verifiers and their expiry checks are untouched.

The six returned subject scalars are ordinary observations. A separate private
finalization derivation also returns the complete typed request and exact input
bytes from this same replay, using bounded sibling hints already authenticated
by the finalization's complete-vector replay. Those hints alone prove no live
population. Both outputs must be joined
to the separately authenticated actual execution grant/planning request and the
present caller's recovery purpose. There is no token input, transport, key
creation, signing, storage, SQL, replacement work allowance or fallback clock.
"""
from __future__ import annotations

import time

from serverware import authority_webauthn_registration_signer_response as replay
from serverware import authority_webauthn_registration_source_response as source_response
from serverware import authority_webauthn_registration_source_wire as source_wire


evidence, authority, enrollment = replay.evidence, replay.authority, replay.enrollment
clock, control, source_request = replay.control.clock, replay.control, replay.source_request


class HistoricalRegistrationSignerError(ValueError):
    pass


class _Processing:
    """One private current-processing guard; historical expiry never enters it."""

    def __init__(self, live_window, transport_deadline_ns, work):
        evidence.capture._SharedLedger(work)
        self.window = clock._validate(live_window)
        if transport_deadline_ns is not None:
            evidence.plan.contract._integer(transport_deadline_ns, minimum=1)
        self.bound = (self.window[4] if transport_deadline_ns is None
            else min(self.window[4], transport_deadline_ns))
        self.work = work
        self.last_epoch, self.last_monotonic = self.window[0], self.window[2]
        self.future_floor = 0

    def check(self):
        now = clock._check_on_work(self.window, work=self.work)
        monotonic = evidence.production._callback(self.work, time.monotonic_ns)
        evidence.plan.contract._integer(monotonic, minimum=1)
        if (now < self.last_epoch or now < self.future_floor
                or monotonic < self.last_monotonic or monotonic >= self.bound):
            raise HistoricalRegistrationSignerError(
                "historical signer processing expired, reversed or encountered future observations")
        self.last_epoch, self.last_monotonic = now, monotonic
        return now

    def observe(self, instant, skew):
        evidence.plan.contract._integer(instant, minimum=1)
        evidence.plan.contract._integer(skew, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
        self.future_floor = max(self.future_floor, instant - skew)
        self.check()

    def interval(self, value, maximum_age, skew):
        issued, expires = control._time_pins(value, maximum_age, skew)
        self.observe(issued, skew)
        return issued, expires


def _enrollment_on_work(original, *, scope, public_key, maximum_age, skew, processing, work):
    """Authenticate the old enrollment signature and original evaluation join."""
    ledger = evidence.capture._SharedLedger(work)
    if not isinstance(public_key, enrollment.plan.Ed25519PublicKey):
        raise HistoricalRegistrationSignerError("historical enrollment issuer is not Ed25519")
    value = evidence.wire._decode_object(original, work=work,
        maximum_bytes=enrollment.MAX_BYTES, maximum_nodes=enrollment.MAX_NODES,
        maximum_depth=enrollment.MAX_DEPTH)
    value = enrollment._capture(value, work)
    enrollment._shape(value)
    evidence.capability._canonical(original, value, ledger, enrollment.MAX_BYTES, enrollment.MAX_NODES)
    work.prepare_copy(value)
    unsigned = value.copy()
    signature = unsigned.pop("signatureBase64Url")
    unsigned_bytes = evidence.capability._wire(unsigned, ledger, enrollment.MAX_BYTES, enrollment.MAX_NODES)
    evidence.capability._signature(public_key, signature, enrollment.SCHEMA, unsigned_bytes, ledger)
    evidence.capability._canonical(original, value, ledger, enrollment.MAX_BYTES, enrollment.MAX_NODES)
    evidence.plan._same((value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["issuerId"], value["audienceSpkiDigest"]), scope, work,
        "historical enrollment differs from independently admitted issuer/audience/configuration")
    context = enrollment._capture(value["context"], work)
    enrollment._context_on_owned_work(context, work)
    issued, expires = processing.interval(
        {"issuedAtEpochNs": value["issuedAtEpochNs"], "expiresAtEpochNs": value["expiresAtEpochNs"]},
        maximum_age, skew)
    evaluated = context["verifiedAtEpochNs"]
    if abs(evaluated - issued) > skew or evaluated >= expires:
        raise HistoricalRegistrationSignerError("historical enrollment evaluation escapes its original interval")
    processing.observe(evaluated, skew)
    evidence.capability._canonical(original, value, ledger, enrollment.MAX_BYTES, enrollment.MAX_NODES)
    return context, issued, expires


def _source_request_on_work(original, original_context, *, configured, processing, work):
    """Authenticate the complete detached source context before decoding it."""
    ledger = evidence.capture._SharedLedger(work)
    pins, scope = source_request._scope(configured.pins,
        configured.generation_sequence, configured.generation_digest)
    public_key = configured.verifier_public_key
    if not isinstance(public_key, source_request.plan.Ed25519PublicKey):
        raise HistoricalRegistrationSignerError("historical source verifier is not Ed25519")
    value, signature, unsigned_wire = source_request._read_control(original, work)
    body = value["contextBytesDigest"], value["contextByteCount"]
    timing = {"issuedAtEpochNs": value["issuedAtEpochNs"], "expiresAtEpochNs": value["expiresAtEpochNs"]}
    signed_scope = (value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["operation"])
    evidence.capability._signature(public_key, signature, source_request.SCHEMA, unsigned_wire, ledger)
    evidence.capability._canonical(original, value, ledger,
        source_request.MAX_CONTROL_BYTES, source_request.MAX_CONTROL_NODES)
    evidence.plan._same(signed_scope, scope, work,
        "historical source request differs from independent configuration/generation/operation")
    evidence.keys._public_binding(pins[1], pins[3], work)
    control._distinct_keys(pins[1], public_key, work)
    issued, expires = processing.interval(timing, configured.maximum_control_age_ns, pins[9])
    evidence.plan._same((source_request.retention._bytes_digest(original_context, work), len(original_context)),
        body, work, "historical source request differs from its complete context bytes")
    processing.check()
    decoded = evidence.wire._decode_object(original_context, work=work,
        maximum_bytes=source_request.MAX_CONTEXT_BYTES, maximum_nodes=source_request.MAX_CONTEXT_NODES,
        maximum_depth=source_request.MAX_CONTEXT_DEPTH)
    context = evidence.capture._JSONCapture(ledger,
        maximum_bytes=source_request.MAX_CONTEXT_BYTES).visit(decoded)
    source_request._context_shape(context)
    evidence.capability._canonical(original_context, context, ledger,
        source_request.MAX_CONTEXT_BYTES, source_request.MAX_CONTEXT_NODES)
    if expires > context["deadlineEpochNs"]:
        raise HistoricalRegistrationSignerError("historical source request exceeds its original context deadline")
    processing.check()
    evidence.capability._canonical(original_context, context, ledger,
        source_request.MAX_CONTEXT_BYTES, source_request.MAX_CONTEXT_NODES)
    return context, issued, expires


def _source_response_on_work(original, request_control, source_bytes, *, configured,
        request_issued, request_expires, processing, work):
    """Authenticate the request control and entire source body before replay."""
    ledger = evidence.capture._SharedLedger(work)
    originals = source_response._originals(request_control, source_bytes)
    pins, scope = source_request._scope(configured.pins,
        configured.generation_sequence, configured.generation_digest)
    planner_key, verifier_key = pins[1], configured.verifier_public_key
    value, signature, unsigned_wire = source_response._read_control(original, work)
    body = tuple((value[name + "BytesDigest"], value[name + "ByteCount"])
        for name in source_response._BODY_NAMES)
    timing = {"issuedAtEpochNs": value["issuedAtEpochNs"], "expiresAtEpochNs": value["expiresAtEpochNs"]}
    signed_scope = (value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["operation"])
    evidence.keys._public_binding(planner_key, pins[3], work)
    evidence.capability._signature(planner_key, signature, source_response.SCHEMA, unsigned_wire, ledger)
    evidence.capability._canonical(original, value, ledger,
        source_response.MAX_CONTROL_BYTES, source_response.MAX_CONTROL_NODES)
    evidence.plan._same(signed_scope, scope, work,
        "historical source response differs from independent configuration/generation/operation")
    control._distinct_keys(planner_key, verifier_key, work)
    actual = tuple((source_response.retention._bytes_digest(raw, work), len(raw)) for raw in originals)
    evidence.plan._same(actual, body, work,
        "historical source response differs from original request control or complete source bytes")
    issued, expires = processing.interval(timing, configured.maximum_control_age_ns, pins[9])
    if expires != request_expires or issued < request_issued - pins[9]:
        raise HistoricalRegistrationSignerError("historical source response changed the original request interval")
    processing.check()


def _evidence_on_work(original, *, claims, public_key, identity, signer_spki,
        expected_times, maximum_age, skew, processing, work):
    """Verify the real evidence signature against genuinely rederived claims."""
    ledger = evidence.capture._SharedLedger(work)
    purpose = "registration-attestation"
    evidence._claims(claims, purpose)
    evidence._identity(identity)
    evidence.plan.contract._digest(signer_spki)
    expected = evidence._Capture(ledger, maximum_bytes=evidence.MAX_EVIDENCE_BYTES).visit(
        {"claims": claims, "signerIdentity": identity})
    envelope = evidence._decode_on_work(original, work)
    work.prepare_copy(envelope)
    unsigned = envelope.copy()
    signature = unsigned.pop("signatureBase64Url")
    unsigned_bytes = evidence.capability._wire(unsigned, ledger,
        evidence.MAX_EVIDENCE_BYTES, evidence.MAX_EVIDENCE_NODES)
    evidence.keys._public_binding(public_key, signer_spki, work)
    evidence.capability._signature(public_key, signature, evidence.SIGNATURE_DOMAIN, unsigned_bytes, ledger)
    evidence.capability._canonical(unsigned_bytes, unsigned, ledger,
        evidence.MAX_EVIDENCE_BYTES, evidence.MAX_EVIDENCE_NODES)
    evidence.capability._canonical(original, envelope, ledger,
        evidence.MAX_EVIDENCE_BYTES, evidence.MAX_EVIDENCE_NODES)
    evidence.plan._same((unsigned["purpose"], unsigned["signerSpkiDigest"],
            unsigned["signerIdentity"], unsigned["claims"]),
        (purpose, signer_spki, expected["signerIdentity"], expected["claims"]), work,
        "historical evidence differs from independent purpose, signer or genuinely replayed claims")
    timing = {"issuedAtEpochNs": envelope["issuedAtEpochNs"], "expiresAtEpochNs": envelope["expiresAtEpochNs"]}
    actual_times = processing.interval(timing, maximum_age, skew)
    evidence.plan._same(actual_times, expected_times, work,
        "historical evidence interval differs from the original ceremony and row deadlines")
    processing.check()
    evidence.capability._canonical(original, envelope, ledger,
        evidence.MAX_EVIDENCE_BYTES, evidence.MAX_EVIDENCE_NODES)


def _replay_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, request_originals, response_originals,
        finalization, sibling_challenge_ids, live_window, work, transport_deadline_ns=None):
    """One genuine historical replay; only the fixed output derivation differs."""
    ledger = evidence.capture._SharedLedger(work)
    if (type(finalization) is not bool or type(sibling_challenge_ids) is not list
            or len(sibling_challenge_ids) > replay.production.registration.MAX_SIBLINGS
            or not finalization and sibling_challenge_ids
            or any(type(value) is not str or not 1 <= len(value) <= 4096
                for value in sibling_challenge_ids)):
        raise HistoricalRegistrationSignerError("historical finalization sibling hints are not source bounded")
    siblings = evidence.capture._JSONCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(sibling_challenge_ids)
    work.prepare_scan(siblings)
    previous = None
    for value in siblings:
        replay.production.registration._text(value, "sibling challenge ID", 4096, work)
        if previous is not None:
            work.prepare_comparison(previous, value)
            if previous >= value:
                raise HistoricalRegistrationSignerError("historical finalization sibling hints are not sorted unique")
        previous = value
    request_raw = replay.wire._request_originals(request_originals)
    response_raw = replay.wire._response_originals(response_originals)
    if sum(len(raw) for raw in (*request_raw, *response_raw)) > authority.MAX_RESULT_BYTES:
        raise HistoricalRegistrationSignerError("historical signer originals exceed the combined raw10 bound")
    digest = configuration_digest
    evidence.plan.contract._digest(digest)
    if type(payload) is not dict or type(generation) is not dict:
        raise HistoricalRegistrationSignerError("historical signer configuration is not exact data")
    replay.configuration.capability.shape._bounded_object(generation, 24, "historical signer launch context")
    owned_payload = replay.configuration._ConfigurationCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(generation)
    owned_runtime = evidence.capture._JSONCapture(ledger, maximum_bytes=8192).visit(runtime_role_identities)
    processing = _Processing(live_window, transport_deadline_ns, work)
    processing.check()
    credential_id, transports, instant = replay.wire._decode_request_on_work(request_raw, work=work)
    verified_ns = replay.production.registration._now(instant)
    replay.production.registration._integer(verified_ns, "historical registration evaluation", 1)
    configured = replay.enrollment_policy._capture_on_work(payload=owned_payload,
        configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, work=work)
    policy, issuer_key = configured.policy, configured.issuer_public_key
    sequence, generation_digest = configured.generation_sequence, configured.generation_digest
    issuer_id, audience, grant_age, grant_skew = (policy["issuerId"],
        policy["audienceSigningSpkiDigest"], policy["maximumAgeNs"], policy["maximumClockSkewNs"])
    purposes, keys = replay.evidence_policy._validate_policy_on_work(
        owned_payload[replay.evidence_policy.FIELD], webauthn=owned_payload["webauthn"], work=work)
    selected = purposes["registration"]
    if selected is None:
        raise HistoricalRegistrationSignerError("historical registration evidence purpose is disabled")
    public_key = keys["registration"]
    identity = evidence.capture._JSONCapture(ledger).visit(selected["signerIdentity"])
    signer_spki, rp_id, origin, evidence_age, evidence_skew = (
        selected["signingSpkiDigest"], selected["rpId"], selected["origin"],
        selected["maximumAgeNs"], selected["maximumClockSkewNs"])
    evidence.plan._same(audience, signer_spki, work,
        "historical enrollment audience differs from the actual evidence purpose")
    scope = enrollment._scope(digest, sequence, generation_digest, issuer_id,
        audience, grant_age, grant_skew)
    processing.check()
    grant_context, grant_issued, grant_expires = _enrollment_on_work(request_raw[4],
        scope=scope, public_key=issuer_key, maximum_age=grant_age, skew=grant_skew,
        processing=processing, work=work)
    grant_context_bytes = evidence.capability._wire(grant_context, ledger,
        enrollment.MAX_BYTES, enrollment.MAX_NODES)
    enrollment._bind_originals_on_work(context=grant_context,
        client_data_json=request_raw[5], attestation_object=request_raw[6],
        credential_id=credential_id, transports=transports, verified_at_epoch_ns=verified_ns, work=work)
    source_configuration = replay.admission.configuration._capture_on_work(purpose="registration",
        payload=owned_payload, configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, work=work)
    evidence.plan._same((source_configuration.generation_sequence, source_configuration.generation_digest),
        (sequence, generation_digest), work, "historical signer source generation differs")
    processing.check()
    context, issued, expires = _source_request_on_work(request_raw[0], request_raw[1],
        configured=source_configuration, processing=processing, work=work)
    _source_response_on_work(request_raw[2], request_raw[0], request_raw[3],
        configured=source_configuration, request_issued=issued, request_expires=expires,
        processing=processing, work=work)
    source_skew = source_configuration.pins[9]
    observed = source_wire._verify_on_work(source_bytes=request_raw[3], request_context=context,
        request_issued_at_epoch_ns=issued, request_expires_at_epoch_ns=expires,
        maximum_clock_skew_ns=source_skew, work=work)
    processing.check()
    challenge, publication, session = (context["registrationChallengeId"],
        context["publishedPublicationId"], context["oidcSessionId"])
    cutoff_ns = replay.production.registration._now(observed.database_now)
    evidence.plan._same((grant_context["registrationChallengeId"], grant_context["oidcSessionId"],
        grant_context["rpId"], grant_context["origin"]), (challenge, session, rp_id, origin), work,
        "historical enrollment differs from authenticated source selectors or configured RP/origin")
    if (verified_ns < issued - source_skew or verified_ns >= expires
            or verified_ns >= context["deadlineEpochNs"]
            or abs(verified_ns - issued) > source_skew or abs(verified_ns - cutoff_ns) > source_skew):
        raise HistoricalRegistrationSignerError("historical evaluation differs from its source interval or cutoff")
    processing.observe(verified_ns, source_skew)
    processing.observe(cutoff_ns, source_skew)
    rows = replay.source._verify_on_work(registration_challenge_id=challenge,
        published_publication_id=publication, oidc_session_id=session,
        business_before_roots=observed.business_before_roots,
        authorization_before_roots=observed.authorization_before_roots,
        selected_rows=observed.selected_rows, before_proofs=observed.before_proofs,
        query_reads=observed.query_reads, work=work)
    challenge_row, high_water, published_row, session_row = (
        rows.challenge_row, rows.high_water_row, rows.published_row, rows.oidc_session_row)
    derived = replay.ceremony._derive_on_work(client_data_json=request_raw[5],
        attestation_object=request_raw[6], credential_id=credential_id, transports=transports,
        challenge_row=challenge_row, user_id=grant_context["userId"], label=grant_context["label"],
        expected_authorization=grant_context["expectedAuthorization"], rp_id=rp_id, origin=origin, work=work)
    verification_context = replay.trust._context_on_work(published_row=published_row,
        high_water_row=high_water, rp_id=rp_id, origin=origin, verified_at=instant, work=work)
    processing.check()
    claims, finalization_arguments, expected_identity, evidence_issued, evidence_expires = replay.production._claims_on_work(
        client_data_json=derived.client_data_json, attestation_object=derived.attestation_object,
        credential_id=derived.credential_id, transports=derived.transports,
        scope=derived.scope, verification_context=verification_context,
        challenge_row=challenge_row, expected_authorization=grant_context["expectedAuthorization"],
        high_water_row=high_water, published_row=published_row, oidc_session_row=session_row,
        sibling_challenge_ids=siblings, signer_identity=identity, maximum_age_ns=evidence_age, work=work)
    processing.check()
    _evidence_on_work(response_raw[0], claims=claims, public_key=public_key,
        identity=expected_identity, signer_spki=signer_spki,
        expected_times=(evidence_issued, evidence_expires), maximum_age=evidence_age,
        skew=evidence_skew, processing=processing, work=work)
    if max(grant_issued, issued, evidence_issued) >= min(
            grant_expires, expires, evidence_expires, context["deadlineEpochNs"]):
        raise HistoricalRegistrationSignerError("historical signer original intervals do not intersect")
    request, regenerated_inputs = replay.invocation._registration_on_work(
        envelope_bytes=response_raw[0], client_data_json=derived.client_data_json,
        attestation_object=derived.attestation_object, credential_id=derived.credential_id,
        transports=derived.transports, scope=derived.scope, verification_context=verification_context,
        expected_authorization=grant_context["expectedAuthorization"], published_row=published_row,
        oidc_session_row=session_row, work=work)
    work.charge(input_bytes=len(regenerated_inputs) + len(response_raw[1]))
    if regenerated_inputs != response_raw[1]:
        raise HistoricalRegistrationSignerError("historical signer returned inputs differ from genuine replay")
    request_bytes = evidence.capability._wire(request, ledger,
        authority.MAX_REQUEST_BYTES, source_request.MAX_CONTEXT_NODES)
    processing.check()
    evidence.capability._canonical(grant_context_bytes, grant_context, ledger,
        enrollment.MAX_BYTES, enrollment.MAX_NODES)
    evidence.capability._canonical(request_raw[1], context, ledger,
        source_request.MAX_CONTEXT_BYTES, source_request.MAX_CONTEXT_NODES)
    evidence.capability._canonical(request_bytes, request, ledger,
        authority.MAX_REQUEST_BYTES, source_request.MAX_CONTEXT_NODES)
    subject = {"userId": grant_context["userId"], "challengeId": grant_context["registrationChallengeId"],
        "sessionId": grant_context["oidcSessionId"], "mode": grant_context["expectedAuthorization"]["mode"],
        "requestDigest": request["requestDigest"], "operationId": request["operationId"]}
    if not finalization:
        return subject
    final_request = replay._finalization_request_on_work(finalization_arguments, response_raw[0], work)
    final_inputs = replay.registration_replay._encode_inputs_on_work(work=work)
    processing.check()
    return subject, final_request, final_inputs


def _verify_subject_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, request_originals, response_originals,
        live_window, work, transport_deadline_ns=None):
    """Return six original subject scalars, never present recovery permission."""
    return _replay_on_configuration(payload=payload, configuration_digest=configuration_digest,
        generation=generation, runtime_role_identities=runtime_role_identities,
        request_originals=request_originals, response_originals=response_originals,
        finalization=False, sibling_challenge_ids=[], live_window=live_window,
        work=work, transport_deadline_ns=transport_deadline_ns)


def _verify_finalization_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, request_originals, response_originals,
        sibling_challenge_ids, live_window, work, transport_deadline_ns=None):
    """Return (evidence subject, finalization request, exact finalization inputs).

    The consumer must compare the complete request and inputs to the actual
    historical finalization replay and join the evidence subject to the actual
    evidence exchange. No historical timestamp becomes now, original interval
    is renewed, successful token is accepted or present permission is returned.
    """
    return _replay_on_configuration(payload=payload, configuration_digest=configuration_digest,
        generation=generation, runtime_role_identities=runtime_role_identities,
        request_originals=request_originals, response_originals=response_originals,
        finalization=True, sibling_challenge_ids=sibling_challenge_ids,
        live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)
