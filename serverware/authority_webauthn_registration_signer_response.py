"""Replay a fixed signer's raw response without accepting parallel metadata.

The caller supplies the actual admitted configuration/generation/runtime cohort
and its original eight-part signing request. The enrollment grant and both
source controls are genuinely authenticated on this work; raw source proofs
are replayed before deriving ceremony and published trust inputs. The actual
attestation then derives the complete expected claims for the configured
registration-evidence key. No returned scope, root, DER or row is enrolled.

Only original evidence-envelope and input-codec bytes cross the response
boundary. The evidence-admission request and complete input codec are genuinely
regenerated here and compared to the response. The ordinary returned pair is
not evidence admission, custody, finalization, execution or enrollment proof.
Sibling hints stay fixed empty for the evidence-only continuation. The separate
fixed finalization continuation derives a typed request from the same genuine
replay and bounded hints, not unsigned response metadata. Complete OIDC history
and siblings, an actual unconsumed v2 evidence receipt and current-root/business
authority still belong to the downstream transition planner and kernel.
No private key, signing, grant consumption, store, socket or new work is used.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_revocation_configuration as configuration
from serverware import authority_request_commitment as commitment
from serverware import authority_webauthn_enrollment_authorization as enrollment
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import authority_webauthn_evidence_policy as evidence_policy
from serverware import authority_webauthn_evidence_custody_wire as control
from serverware import authority_webauthn_evidence_invocation as invocation
from serverware import authority_webauthn_registration_ceremony as ceremony
from serverware import authority_webauthn_registration_production as production
from serverware import authority_webauthn_registration_replay as registration_replay
from serverware import authority_webauthn_registration_signer_wire as wire
from serverware import authority_webauthn_registration_source_admission as admission
from serverware import authority_webauthn_registration_source_proofs as source
from serverware import authority_webauthn_registration_source_request as source_request
from serverware import authority_webauthn_registration_trust as trust
from serverware import authority_webauthn_transition_proof_contract as transition_contract


authority, evidence = production.authority, production.evidence


class WebAuthnRegistrationSignerResponseError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ExecutionRequestOriginals:
    """Same-call replay outputs, never an accepted authorization input."""

    request: dict
    generation_digest: str
    planner_public_key: object
    evidence_public_key: object
    excluded_caller_spkis: tuple
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    deadline_ns: int
    last_epoch_ns: int


def _fresh(*, grant_context, grant_timing, grant_window, grant_age, grant_skew,
        source_timing, source_window, source_age, source_skew, verified_ns, work):
    enrollment._fresh(grant_context, grant_timing, window=grant_window,
        maximum_age_ns=grant_age, maximum_clock_skew_ns=grant_skew, work=work)
    now = control._fresh_on_work(source_timing, window=source_window,
        maximum_age_ns=source_age, maximum_clock_skew_ns=source_skew, work=work)
    # Recheck the earlier grant's signed interval at the last actual sample;
    # no source sample can renew the distinct enrollment interval.
    evidence._fresh(grant_timing, now, grant_age, grant_skew)
    if verified_ns > now + source_skew:
        raise WebAuthnRegistrationSignerResponseError("original registration evaluation is future-dated")
    return now


def _finalization_request_on_work(arguments, envelope_bytes, work):
    """Derive commitments from this invocation's actual claims replay only."""
    registration = production.registration
    operation = registration.OPERATION
    arguments["attestation_envelope_base64url"] = registration.invocation._encode(envelope_bytes, work)
    arguments["attestation_evidence_digest"] = evidence._evidence_digest_on_work(envelope_bytes, work)
    arguments["businessIntent"] = authority._synthesize_business_intent(operation, arguments, work=work)
    registration._arguments(arguments, work)
    request = {"schema": transition_contract.shape.TYPED_REQUEST_SCHEMA,
        "operation": operation, "operationId": None, "requestDigest": None,
        "handler": authority.operation_spec(operation)["handler"],
        "operationManifestDigest": authority.OPERATION_MANIFEST_DIGEST,
        "arguments": arguments}
    # These two excluded output fields are filled with the genuine shared
    # commitment computation before anything is exposed to another component.
    digest = commitment._typed_request_digest(request, work=work)
    work.prepare_utf8(operation)
    work.prepare_utf8(digest)
    work.charge(hashes=1)
    request["requestDigest"] = digest
    request["operationId"] = commitment.operation_id(operation, digest)
    owned = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work),
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(request)
    transition_contract._request(owned, operation)
    return owned


def _verify_on_configuration_core(*, finalization, sibling_challenge_ids, execution=False,
        payload, configuration_digest, generation, runtime_role_identities,
        request_originals, response_originals, work):
    """One genuine replay; only the fixed output derivation differs."""
    ledger = evidence.capture._SharedLedger(work)
    if (type(finalization) is not bool or type(execution) is not bool
            or execution and finalization or type(sibling_challenge_ids) is not list
            or len(sibling_challenge_ids) > production.registration.MAX_SIBLINGS
            or not finalization and sibling_challenge_ids
            or any(type(value) is not str or not 1 <= len(value) <= 4096
                for value in sibling_challenge_ids)):
        raise WebAuthnRegistrationSignerResponseError("registration sibling hints are not source bounded")
    siblings = evidence.capture._JSONCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(sibling_challenge_ids)
    work.prepare_scan(siblings)
    previous = None
    for value in siblings:
        production.registration._text(value, "sibling challenge ID", 4096, work)
        if previous is not None:
            work.prepare_comparison(previous, value)
            if previous >= value:
                raise WebAuthnRegistrationSignerResponseError("registration sibling hints are not sorted unique")
        previous = value
    request_raw = wire._request_originals(request_originals)
    response_raw = wire._response_originals(response_originals)
    digest = configuration_digest
    evidence.plan.contract._digest(digest)
    if type(payload) is not dict or type(generation) is not dict:
        raise WebAuthnRegistrationSignerResponseError("signer response configuration is not exact data")
    configuration.capability.shape._bounded_object(generation, 24, "signer response launch context")
    # Raw exact-byte tuples and all caller-owned configuration/cohort graphs
    # are detached before metadata decode or the first native key callback.
    owned_payload = configuration._ConfigurationCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(generation)
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    credential_id, transports, instant = wire._decode_request_on_work(request_raw, work=work)
    verified_ns = production.registration._now(instant)
    production.registration._integer(verified_ns, "original registration evaluation", 1)

    configured = enrollment_policy._capture_on_work(payload=owned_payload,
        configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, work=work)
    policy = configured.policy
    issuer_key = configured.issuer_public_key
    sequence, generation_digest = configured.generation_sequence, configured.generation_digest
    issuer_id, audience, grant_age, grant_skew = (policy["issuerId"],
        policy["audienceSigningSpkiDigest"], policy["maximumAgeNs"], policy["maximumClockSkewNs"])
    purposes, keys = evidence_policy._validate_policy_on_work(
        owned_payload[evidence_policy.FIELD], webauthn=owned_payload["webauthn"], work=work)
    selected = purposes["registration"]
    if selected is None:
        raise WebAuthnRegistrationSignerResponseError("registration evidence purpose is disabled")
    public_key = keys["registration"]
    identity = evidence.capture._JSONCapture(ledger).visit(selected["signerIdentity"])
    signer_spki, rp_id, origin, evidence_age, evidence_skew = (
        selected["signingSpkiDigest"], selected["rpId"], selected["origin"],
        selected["maximumAgeNs"], selected["maximumClockSkewNs"])
    evidence.plan._same(audience, signer_spki, work,
        "enrollment grant audience differs from actual registration evidence purpose")

    grant = enrollment._verify_on_work(authorization_bytes=request_raw[4],
        configuration_digest=digest, generation_sequence=sequence,
        generation_digest=generation_digest, issuer_id=issuer_id,
        issuer_public_key=issuer_key, audience_spki_digest=audience,
        maximum_age_ns=grant_age, maximum_clock_skew_ns=grant_skew, work=work)
    grant_context = enrollment._capture(grant.context, work)
    grant_window = grant.window
    grant_timing = {"issuedAtEpochNs": grant.issued_at_epoch_ns,
        "expiresAtEpochNs": grant.expires_at_epoch_ns}
    grant_context_bytes = evidence.capability._wire(grant_context, ledger,
        enrollment.MAX_BYTES, enrollment.MAX_NODES)
    enrollment._bind_originals_on_work(context=grant_context,
        client_data_json=request_raw[5], attestation_object=request_raw[6],
        credential_id=credential_id, transports=transports,
        verified_at_epoch_ns=verified_ns, work=work)

    admitted = admission._verify_on_configuration(payload=owned_payload,
        configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, request_control_bytes=request_raw[0],
        request_context_bytes=request_raw[1], response_control_bytes=request_raw[2],
        source_bytes=request_raw[3], work=work)
    # These are the immediately preceding genuine replay's observations, not
    # an accepted external success carrier. Hold every selector/time first.
    context, observed = admitted.context, admitted.observations
    challenge, publication, session = (context["registrationChallengeId"],
        context["publishedPublicationId"], context["oidcSessionId"])
    deadline = context["deadlineEpochNs"]
    issued, expires, source_window = (admitted.issued_at_epoch_ns,
        admitted.expires_at_epoch_ns, admitted.window)
    source_age, source_skew = admitted.maximum_control_age_ns, admitted.maximum_clock_skew_ns
    source_timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    business, authorization_roots = observed.business_before_roots, observed.authorization_before_roots
    selected_rows, before_proofs, query_reads = observed.selected_rows, observed.before_proofs, observed.query_reads
    cutoff_ns = production.registration._now(observed.database_now)
    evidence.plan._same((grant_context["registrationChallengeId"], grant_context["oidcSessionId"],
        grant_context["rpId"], grant_context["origin"]),
        (challenge, session, rp_id, origin), work,
        "original grant differs from authenticated source selectors or configured RP/origin")
    if (verified_ns < issued - source_skew or verified_ns >= expires or verified_ns >= deadline
            or abs(verified_ns - issued) > source_skew or abs(verified_ns - cutoff_ns) > source_skew):
        raise WebAuthnRegistrationSignerResponseError("original evaluation differs from source interval or cutoff")
    freshness = {"grant_context": grant_context, "grant_timing": grant_timing,
        "grant_window": grant_window, "grant_age": grant_age, "grant_skew": grant_skew,
        "source_timing": source_timing, "source_window": source_window,
        "source_age": source_age, "source_skew": source_skew, "verified_ns": verified_ns,
        "work": work}
    _fresh(**freshness)
    rows = source._verify_on_work(registration_challenge_id=challenge,
        published_publication_id=publication, oidc_session_id=session,
        business_before_roots=business, authorization_before_roots=authorization_roots,
        selected_rows=selected_rows, before_proofs=before_proofs, query_reads=query_reads, work=work)
    challenge_row, high_water, published_row, session_row = (
        rows.challenge_row, rows.high_water_row, rows.published_row, rows.oidc_session_row)
    derived = ceremony._derive_on_work(client_data_json=request_raw[5],
        attestation_object=request_raw[6], credential_id=credential_id,
        transports=transports, challenge_row=challenge_row, user_id=grant_context["userId"],
        label=grant_context["label"], expected_authorization=grant_context["expectedAuthorization"],
        rp_id=rp_id, origin=origin, work=work)
    verification_context = trust._context_on_work(published_row=published_row,
        high_water_row=high_water, rp_id=rp_id, origin=origin, verified_at=instant, work=work)
    claims, finalization_arguments, expected_identity, evidence_issued, evidence_expires = production._claims_on_work(
        client_data_json=derived.client_data_json, attestation_object=derived.attestation_object,
        credential_id=derived.credential_id, transports=derived.transports,
        scope=derived.scope, verification_context=verification_context,
        challenge_row=challenge_row, expected_authorization=grant_context["expectedAuthorization"],
        high_water_row=high_water, published_row=published_row, oidc_session_row=session_row,
        sibling_challenge_ids=siblings, signer_identity=identity, maximum_age_ns=evidence_age, work=work)
    now = _fresh(**freshness)
    evidence._verify_on_work(envelope_bytes=response_raw[0], purpose="registration-attestation",
        expected_claims=claims, public_key=public_key, expected_signer_identity=expected_identity,
        expected_signer_spki_digest=signer_spki, now_epoch_ns=now,
        maximum_age_ns=evidence_age, maximum_clock_skew_ns=evidence_skew, work=work)
    # Decode only the just-authenticated evidence envelope, never the returned
    # input codec as an authority source. Its original interval is not renewed
    # or confused with either source-read or enrollment-grant expiry.
    envelope = evidence._decode_on_work(response_raw[0], work)
    evidence.plan._same((envelope["issuedAtEpochNs"], envelope["expiresAtEpochNs"]),
        (evidence_issued, evidence_expires), work,
        "signed evidence interval differs from the original ceremony and admitted row deadlines")
    evidence_timing = {"issuedAtEpochNs": evidence_issued, "expiresAtEpochNs": evidence_expires}
    request, regenerated_inputs = invocation._registration_on_work(
        envelope_bytes=response_raw[0], client_data_json=derived.client_data_json,
        attestation_object=derived.attestation_object, credential_id=derived.credential_id,
        transports=derived.transports, scope=derived.scope, verification_context=verification_context,
        expected_authorization=grant_context["expectedAuthorization"], published_row=published_row,
        oidc_session_row=session_row, work=work)
    work.charge(input_bytes=len(regenerated_inputs) + len(response_raw[1]))
    if regenerated_inputs != response_raw[1]:
        raise WebAuthnRegistrationSignerResponseError("returned input originals differ from actual authenticated replay")
    returned_inputs = response_raw[1]
    if finalization:
        # Sibling hints do not enter signed attestation claims and are never
        # treated as population proof here. The actual complete-query engine
        # and kernel must prove their exact live population at its own cutoff.
        request = _finalization_request_on_work(finalization_arguments, response_raw[0], work)
        returned_inputs = registration_replay._encode_inputs_on_work(work=work)
    request_bytes = evidence.capability._wire(request, ledger,
        authority.MAX_REQUEST_BYTES, source_request.MAX_CONTEXT_NODES)
    now = _fresh(**freshness)
    evidence._fresh(evidence_timing, now, evidence_age, evidence_skew)
    evidence.capability._canonical(grant_context_bytes, grant_context, ledger,
        enrollment.MAX_BYTES, enrollment.MAX_NODES)
    evidence.capability._canonical(request_raw[1], context, ledger,
        source_request.MAX_CONTEXT_BYTES, source_request.MAX_CONTEXT_NODES)
    evidence.capability._canonical(request_bytes, request, ledger,
        authority.MAX_REQUEST_BYTES, source_request.MAX_CONTEXT_NODES)
    if not execution:
        return request, returned_inputs

    # The dedicated execution-request issuer needs the actual configured keys
    # and the intersection of the ORIGINAL authenticated lifetimes. Neither a
    # new replay instant nor a returned request can renew those controls. This
    # branch adds no work or behavior to the existing pair-returning APIs.
    original_issued = max(grant.issued_at_epoch_ns, issued, evidence_issued)
    original_expires = min(grant.expires_at_epoch_ns, expires, evidence_expires, deadline)
    inherited_deadline = min(grant_window[4], source_window[4])
    if original_expires <= original_issued:
        raise WebAuthnRegistrationSignerResponseError("execution request original intervals do not intersect")
    custody = admission.configuration._capture_on_work(purpose="registration",
        payload=owned_payload, configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, work=work)
    evidence.plan._same(custody.generation_digest, generation_digest, work,
        "execution request source generation changed")
    # All actual role pins come from this same root-admitted configuration,
    # never parallel caller keys. Reject reuse of even the older enrollment
    # issuer: its signature has a different purpose and audience.
    role_pins = []
    work.prepare_scan(owned_payload["roles"])
    for role in owned_payload["roles"].values():
        for field in ("signingSpkiDigest", "responseSigningSpkiDigest"):
            if field in role:
                evidence.plan.contract._digest(role[field])
                role_pins.append(role[field])
    for key in (issuer_key, public_key, custody.pins[1]):
        role_pins.append(evidence.keys._spki_on_work(key, work))
    work.prepare_copy(role_pins)
    excluded_pins = tuple(role_pins)
    now = _fresh(**freshness)
    evidence._fresh(evidence_timing, now, evidence_age, evidence_skew)
    evidence.capability._canonical(request_bytes, request, ledger,
        authority.MAX_REQUEST_BYTES, source_request.MAX_CONTEXT_NODES)
    return _ExecutionRequestOriginals(request, generation_digest, custody.pins[1],
        public_key, excluded_pins, original_issued, original_expires, inherited_deadline, now)


def _verify_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, request_originals, response_originals, work):
    """Return (regenerated evidence-admit request, original input bytes) only."""
    return _verify_on_configuration_core(finalization=False, sibling_challenge_ids=[],
        payload=payload, configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, request_originals=request_originals,
        response_originals=response_originals, work=work)


def _verify_execution_request_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, request_originals, response_originals, work):
    """Replay original evidence for a separately authorized execution issuer.

    This does not turn the old evidence-signing grant into execution permission.
    The actual caller still needs a distinct root-delegated purpose and key.
    No successful replay object is accepted as input to an issuance API.
    """
    return _verify_on_configuration_core(finalization=False, execution=True,
        sibling_challenge_ids=[], payload=payload, configuration_digest=configuration_digest,
        generation=generation, runtime_role_identities=runtime_role_identities,
        request_originals=request_originals, response_originals=response_originals, work=work)


def _verify_finalization_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, request_originals, response_originals, sibling_challenge_ids, work):
    """Return a finalization invocation, not population or execution authority.

    Original grant/source/attestation/evidence and returned input bytes are
    genuinely replayed here. The downstream real transition acquisition must
    still establish full history/siblings and consume the v2 business receipt.
    """
    return _verify_on_configuration_core(finalization=True, sibling_challenge_ids=sibling_challenge_ids,
        payload=payload, configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, request_originals=request_originals,
        response_originals=response_originals, work=work)
