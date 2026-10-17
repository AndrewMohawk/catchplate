"""Issue fixed enrollment grants using an explicit dedicated control-plane key.

The control plane is the enrollment authority: its actual authenticated route
must supply current actor/session admission, the matching enrollment policy and
browser originals. This private producer binds that admitted decision; it does
not turn a caller's identity strings or source rows into authentication. The
independently admitted configuration selects the dedicated issuer and evidence
recipient. No HTTP response, verifier or planner key is substituted.

All request graphs and actual key/time references are held before native
callbacks. The result is original signed bytes, not an evidence signature or
business execution grant. The independent signer must authenticate and durably
consume this grant before producing evidence. Provisioning, protected key
delivery and public-route orchestration remain separate owner responsibilities.
"""
from __future__ import annotations

from datetime import datetime, timezone

from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_webauthn_enrollment_authorization as authorization
from catchplate import authority_webauthn_enrollment_policy as policy
from catchplate import authority_webauthn_registration_signing as signing


authority, evidence, production = signing.authority, signing.evidence, signing.production


class WebAuthnEnrollmentIssuerError(ValueError):
    pass


def _produce_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, enrollment_private_key, client_data_json,
        attestation_object, credential_id, transports, user_id, label,
        expected_authorization, registration_challenge_id, oidc_session_id,
        verified_at, deadline_epoch_ns, work):
    """Bind the actual control-plane admission to one purpose-specific grant."""
    ledger = evidence.capture._SharedLedger(work)
    signer, instant, digest, deadline = (
        enrollment_private_key, verified_at, configuration_digest, deadline_epoch_ns)
    original_client, original_attestation = client_data_json, attestation_object
    if not isinstance(signer, evidence.keys.Ed25519PrivateKey):
        raise WebAuthnEnrollmentIssuerError("enrollment issuance requires its dedicated real Ed25519 key")
    if type(instant) is not datetime or instant.tzinfo is not timezone.utc:
        raise WebAuthnEnrollmentIssuerError("enrollment issuance requires the original exact UTC time")
    verified_ns = production.registration._now(instant)
    production.registration._integer(verified_ns, "original enrollment evaluation time", 1)
    production.registration._integer(deadline, "original enrollment deadline", 1)
    production.registration._digest(digest)
    for raw, maximum in ((original_client, production.attestation.MAX_CLIENT_DATA_JSON_BYTES),
            (original_attestation, production.attestation.MAX_ATTESTATION_OBJECT_BYTES)):
        if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
            raise WebAuthnEnrollmentIssuerError("enrollment issuance requires bounded original browser bytes")
    if type(transports) is not tuple or len(transports) > 16:
        raise WebAuthnEnrollmentIssuerError("enrollment transport inventory is not bounded exact data")
    if type(payload) is not dict or type(generation) is not dict:
        raise WebAuthnEnrollmentIssuerError("enrollment configuration is not exact data")
    configuration.capability.shape._bounded_object(generation, 24, "enrollment launch context")
    work.prepare_copy(transports)
    owned_inputs = evidence.capture._JSONCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit({
            "credentialId": credential_id, "transports": list(transports),
            "userId": user_id, "label": label, "authorization": expected_authorization,
            "challengeId": registration_challenge_id, "sessionId": oidc_session_id})
    owned_payload = configuration._ConfigurationCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(generation)
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    configured = policy._capture_on_work(payload=owned_payload,
        configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, work=work)
    held_policy = configured.policy
    work.prepare_copy(owned_inputs["transports"])
    context = authorization._context_on_work(client_data_json=original_client,
        attestation_object=original_attestation, credential_id=owned_inputs["credentialId"],
        transports=tuple(owned_inputs["transports"]), user_id=owned_inputs["userId"],
        label=owned_inputs["label"], expected_authorization=owned_inputs["authorization"],
        registration_challenge_id=owned_inputs["challengeId"], oidc_session_id=owned_inputs["sessionId"],
        rp_id=owned_payload["webauthn"]["rpId"], origin=owned_payload["webauthn"]["origin"],
        verified_at_epoch_ns=verified_ns, work=work)
    return authorization._produce_on_work(context=context, configuration_digest=digest,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        issuer_id=held_policy["issuerId"], issuer_private_key=signer,
        issuer_public_key=configured.issuer_public_key,
        audience_spki_digest=held_policy["audienceSigningSpkiDigest"],
        maximum_age_ns=held_policy["maximumAgeNs"],
        maximum_clock_skew_ns=held_policy["maximumClockSkewNs"],
        deadline_epoch_ns=deadline, work=work)
