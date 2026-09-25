"""Authenticate original source exchange bytes before dedicated evidence signing.

The independent owner supplies an actually admitted configuration, generation,
runtime cohort, dedicated evidence private key/identity, original browser data,
a signed control-plane enrollment grant, its independently provisioned replay
store, complete sibling selection and original UTC evaluation time. The grant
authenticates enrollment under the explicit dedicated issuer policy; matching
configuration data does not establish owner or prior publication provenance.

Both original transport controls and their byte commitments are verified and
raw memberships/query associations genuinely replayed in this invocation.
Selectors, roots, rows and proofs then come only from that authenticated raw4,
not separate caller inputs or a successful verifier-result carrier. The fixed
existing producer replays those source proofs, derives ceremony/trust inputs,
verifies the real attestation and signs with the explicit registration-evidence
policy/key. Its ordinary envelope/arguments/request/inputs tuple is preserved.

The supplied evaluation time is never chosen from returned bytes or retimed.
The original source-read window remains live through signing and return.
Source-read expiry does not redefine the independently configured evidence
envelope lifetime: those are distinct controls. The grant's original interval
also stays live through signing. Its durable one-attempt marker precedes the
evidence signature; failure after consumption never permits retry or reset.
There is no SQL, socket, public route, role-key fallback, business execution,
custody forwarding or replacement allowance. Local replay storage is not an
independent anti-rollback authority.
"""
from __future__ import annotations

from datetime import datetime, timezone

from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_evidence_custody_wire as wire
from serverware import authority_webauthn_enrollment_authorization as enrollment
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware.authority_webauthn_enrollment_replay import EnrollmentReplayStore
from serverware import authority_webauthn_registration_signing as signing
from serverware import authority_webauthn_registration_source_admission as admission
from serverware import authority_webauthn_registration_source_request as request_wire
from serverware import authority_webauthn_registration_source_response as response_wire


authority, evidence, production = signing.authority, signing.evidence, signing.production


class WebAuthnRegistrationExchangeSigningError(ValueError):
    pass


def _fresh(*, timing, window, maximum_age_ns, maximum_clock_skew_ns, verified_ns, work):
    now = wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    if verified_ns > now + maximum_clock_skew_ns:
        raise WebAuthnRegistrationExchangeSigningError("original registration time is future-dated beyond the admitted skew")


def _produce_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, request_control_bytes, request_context_bytes,
        response_control_bytes, source_bytes, evidence_private_key, evidence_signer_identity,
        enrollment_authorization_bytes, enrollment_replay_store,
        client_data_json, attestation_object, credential_id, transports,
        sibling_challenge_ids, verified_at, work):
    """Return the actual envelope, finalization arguments, request and inputs.

    Raw4 means request control/context and response control/source observations.
    This entrypoint accepts no source selector, root, row, proof, clock override
    or successful admission result. User, label and enrollment authorization
    come only from the genuinely verified grant. The protected, non-rollback
    replay-store lifetime, dedicated signer provenance and original evaluation
    time remain owner duties. Grant consumption is irreversible even when the
    later signer or final freshness check fails.
    """
    ledger = evidence.capture._SharedLedger(work)
    request_originals = request_wire._raw2(request_control_bytes, request_context_bytes)
    response_originals = response_wire._raw2(response_control_bytes, source_bytes)
    original_client, original_attestation = client_data_json, attestation_object
    signer, instant, digest = evidence_private_key, verified_at, configuration_digest
    original_grant, replay_store = enrollment_authorization_bytes, enrollment_replay_store
    if type(original_grant) is not bytes or not 2 <= len(original_grant) <= enrollment.MAX_BYTES:
        raise WebAuthnRegistrationExchangeSigningError("registration requires bounded original enrollment authorization")
    if type(replay_store) is not EnrollmentReplayStore:
        raise WebAuthnRegistrationExchangeSigningError("registration requires its real durable enrollment replay store")
    for raw, maximum in ((original_client, production.attestation.MAX_CLIENT_DATA_JSON_BYTES),
            (original_attestation, production.attestation.MAX_ATTESTATION_OBJECT_BYTES)):
        if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
            raise WebAuthnRegistrationExchangeSigningError("registration exchange signing requires bounded original browser bytes")
    if (type(transports) is not tuple or len(transports) > 16
            or type(sibling_challenge_ids) is not list
            or len(sibling_challenge_ids) > production.registration.MAX_SIBLINGS):
        raise WebAuthnRegistrationExchangeSigningError("registration exchange signing inventories exceed their source bounds")
    if not isinstance(signer, evidence.keys.Ed25519PrivateKey):
        raise WebAuthnRegistrationExchangeSigningError("registration exchange signing requires the dedicated real evidence key")
    if type(instant) is not datetime or instant.tzinfo is not timezone.utc:
        raise WebAuthnRegistrationExchangeSigningError("registration exchange signing requires the original exact UTC time")
    verified_ns = production.registration._now(instant)
    production.registration._integer(verified_ns, "original registration evaluation time", 1)
    production.registration._digest(digest)
    if type(payload) is not dict or type(generation) is not dict:
        raise WebAuthnRegistrationExchangeSigningError("registration exchange configuration is not exact data")
    configuration.capability.shape._bounded_object(generation, 24, "registration exchange launch context")
    # Own all browser metadata, authorization, identity and configuration
    # graphs before admission can invoke keys, hashes, parsing or clocks. Raw
    # originals, the exact UTC time and the dedicated key handle are held once.
    work.prepare_copy(transports)
    owned_inputs = evidence.capture._JSONCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit({
            "credentialId": credential_id, "transports": list(transports),
            "siblings": sibling_challenge_ids, "signerIdentity": evidence_signer_identity})
    owned_payload = configuration._ConfigurationCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(generation)
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    evidence._identity(owned_inputs["signerIdentity"])
    work.prepare_copy(owned_inputs["transports"])
    held_transports = tuple(owned_inputs["transports"])
    configured_grant = enrollment_policy._capture_on_work(payload=owned_payload,
        configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, work=work)
    grant_policy = configured_grant.policy
    grant_age, grant_skew = grant_policy["maximumAgeNs"], grant_policy["maximumClockSkewNs"]
    grant = enrollment._verify_on_work(authorization_bytes=original_grant,
        configuration_digest=digest, generation_sequence=configured_grant.generation_sequence,
        generation_digest=configured_grant.generation_digest,
        issuer_id=grant_policy["issuerId"], issuer_public_key=configured_grant.issuer_public_key,
        audience_spki_digest=grant_policy["audienceSigningSpkiDigest"],
        maximum_age_ns=grant_age, maximum_clock_skew_ns=grant_skew, work=work)
    grant_context = evidence.capture._JSONCapture(ledger,
        maximum_bytes=enrollment.MAX_BYTES).visit(grant.context)
    grant_window, grant_digest = grant.window, grant.authorization_digest
    grant_timing = {"issuedAtEpochNs": grant.issued_at_epoch_ns,
        "expiresAtEpochNs": grant.expires_at_epoch_ns}
    enrollment._bind_originals_on_work(context=grant_context,
        client_data_json=original_client, attestation_object=original_attestation,
        credential_id=owned_inputs["credentialId"], transports=held_transports,
        verified_at_epoch_ns=verified_ns, work=work)
    admitted = admission._verify_on_configuration(payload=owned_payload,
        configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime,
        request_control_bytes=request_originals[0], request_context_bytes=request_originals[1],
        response_control_bytes=response_originals[0], source_bytes=response_originals[1], work=work)
    # These values originate only in the genuine fixed admission immediately
    # above. Snapshot all fields before subsequent native signing/clock work;
    # no externally supplied carrier can enter this continuation.
    context, observed = admitted.context, admitted.observations
    issued, expires, window = admitted.issued_at_epoch_ns, admitted.expires_at_epoch_ns, admitted.window
    maximum_age, skew = admitted.maximum_control_age_ns, admitted.maximum_clock_skew_ns
    challenge, publication, session = (context["registrationChallengeId"],
        context["publishedPublicationId"], context["oidcSessionId"])
    deadline = context["deadlineEpochNs"]
    business, authorization = observed.business_before_roots, observed.authorization_before_roots
    selected, proofs, query_reads = observed.selected_rows, observed.before_proofs, observed.query_reads
    database_now = observed.database_now
    evidence.plan._same((grant_context["registrationChallengeId"], grant_context["oidcSessionId"],
        grant_context["rpId"], grant_context["origin"]),
        (challenge, session, owned_payload["webauthn"]["rpId"], owned_payload["webauthn"]["origin"]),
        work, "enrollment grant differs from authenticated source selectors or configured RP/origin")
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    cutoff_ns = production.registration._now(database_now)
    if (verified_ns < issued - skew or verified_ns >= expires or verified_ns >= deadline
            or abs(verified_ns - issued) > skew or abs(verified_ns - cutoff_ns) > skew):
        raise WebAuthnRegistrationExchangeSigningError("original registration time differs from the authenticated source interval or cutoff")
    _fresh(timing=timing, window=window, maximum_age_ns=maximum_age,
        maximum_clock_skew_ns=skew, verified_ns=verified_ns, work=work)
    _fresh(timing=grant_timing, window=grant_window, maximum_age_ns=grant_age,
        maximum_clock_skew_ns=grant_skew, verified_ns=verified_ns, work=work)
    # Publish and sync the immutable marker before evidence signing. The
    # concrete owner rejects every duplicate, including an identical retry.
    # A slow or uncertain publication can consume the grant without a result;
    # it must never make the signed authority reusable.
    EnrollmentReplayStore.consume(replay_store, grant_digest)
    _fresh(timing=timing, window=window, maximum_age_ns=maximum_age,
        maximum_clock_skew_ns=skew, verified_ns=verified_ns, work=work)
    _fresh(timing=grant_timing, window=grant_window, maximum_age_ns=grant_age,
        maximum_clock_skew_ns=grant_skew, verified_ns=verified_ns, work=work)
    result = signing._produce_from_source_proofs_on_configuration(
        payload=owned_payload, configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, evidence_private_key=signer,
        evidence_signer_identity=owned_inputs["signerIdentity"],
        client_data_json=original_client, attestation_object=original_attestation,
        credential_id=owned_inputs["credentialId"], transports=held_transports,
        user_id=grant_context["userId"], label=grant_context["label"],
        expected_authorization=grant_context["expectedAuthorization"],
        sibling_challenge_ids=owned_inputs["siblings"], verified_at=instant,
        registration_challenge_id=challenge, published_publication_id=publication, oidc_session_id=session,
        business_before_roots=business, authorization_before_roots=authorization,
        selected_rows=selected, before_proofs=proofs, query_reads=query_reads, work=work)
    _fresh(timing=timing, window=window, maximum_age_ns=maximum_age,
        maximum_clock_skew_ns=skew, verified_ns=verified_ns, work=work)
    _fresh(timing=grant_timing, window=grant_window, maximum_age_ns=grant_age,
        maximum_clock_skew_ns=grant_skew, verified_ns=verified_ns, work=work)
    return result
