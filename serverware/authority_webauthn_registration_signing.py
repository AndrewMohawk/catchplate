"""Fixed registration evidence production under an explicit admitted purpose policy.

The owning independent signer must supply the real root-admitted configuration,
active generation/runtime cohort, actual evidence private key and separately
admitted signer identity. It must also independently admit the challenge,
publication/high-water/session rows, enrollment authorization and original
evaluation time. This consistency mapper cannot establish that provenance from
caller dictionaries, possession of a key, or matching identity strings.
The source-proof entrypoint instead replays actual original primary memberships
and exact query/address associations before deriving those rows in this call.
Its independently admitted roots, selectors, enrollment, original clock and
prior publication signature remain upstream authority; raw proofs alone do
not establish them or complete sibling/history populations.

All request graphs and signer references are held before native configuration
or key callbacks. The source-selected purpose supplies RP/origin, public key,
identity, SPKI and lifetime; no request overrides or generic role-key fallback
exist. Genuine row-derived original verification/signing and invocation assembly
run on the same supplied work. No clock, SQL, socket, custody writer, public
route, registry activation or replacement allowance is introduced here.
"""
from __future__ import annotations

from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_evidence_configuration as read_configuration
from serverware import authority_webauthn_evidence_policy as policy
from serverware import authority_webauthn_registration_production as production


authority, evidence = production.authority, production.evidence


class WebAuthnRegistrationSigningError(ValueError):
    pass


def _produce_from_source_proofs_on_configuration(*, payload, configuration_digest,
        generation, runtime_role_identities, evidence_private_key, evidence_signer_identity,
        client_data_json, attestation_object, credential_id, transports, user_id, label,
        expected_authorization, sibling_challenge_ids, verified_at,
        registration_challenge_id, published_publication_id, oidc_session_id,
        business_before_roots, authorization_before_roots, selected_rows,
        before_proofs, query_reads, work):
    """Replay the fixed pre-signing reads, then produce actual original evidence.

    No signed envelope or evidence digest is needed to verify these source rows.
    All original graphs are owned before the genuine primary engine runs;
    the returned row carrier is consumed only inside this same invocation.
    Root/selector provenance, prior publication admission and complete sibling
    state are independent owner responsibilities, not inferred from membership.
    The result remains the ordinary envelope/arguments/request/inputs tuple.
    """
    from serverware import authority_webauthn_registration_source_proofs as source

    ledger = evidence.capture._SharedLedger(work)
    original_client, original_attestation = client_data_json, attestation_object
    for raw, maximum in ((original_client, production.attestation.MAX_CLIENT_DATA_JSON_BYTES),
            (original_attestation, production.attestation.MAX_ATTESTATION_OBJECT_BYTES)):
        if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
            raise WebAuthnRegistrationSigningError("registration source signing requires bounded originals")
    if (type(transports) is not tuple or len(transports) > 16
            or type(sibling_challenge_ids) is not list
            or len(sibling_challenge_ids) > production.registration.MAX_SIBLINGS):
        raise WebAuthnRegistrationSigningError("registration source signing inventory exceeds its bound")
    expected_count = 3 + int(oidc_session_id is not None)
    if (type(business_before_roots) is not tuple or type(authorization_before_roots) is not tuple
            or len(business_before_roots) + len(authorization_before_roots) != 5
            or type(selected_rows) is not tuple or len(selected_rows) != expected_count
            or type(before_proofs) is not tuple or len(before_proofs) != expected_count
            or type(query_reads) is not tuple or len(query_reads) != expected_count):
        raise WebAuthnRegistrationSigningError("registration source proof inventories are not exact")
    signer, instant, digest = evidence_private_key, verified_at, configuration_digest
    if not isinstance(signer, evidence.keys.Ed25519PrivateKey):
        raise WebAuthnRegistrationSigningError("independent evidence signer must be Ed25519")
    production.registration._digest(digest)
    production.registration._integer(production.registration._now(instant), "original registration time", 1)
    work.prepare_copy(transports)
    owned_inputs = evidence.capture._JSONCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit({
            "credentialId": credential_id, "transports": list(transports),
            "userId": user_id, "label": label, "authorization": expected_authorization,
            "siblings": sibling_challenge_ids, "signerIdentity": evidence_signer_identity,
            "challengeId": registration_challenge_id, "publicationId": published_publication_id,
            "sessionId": oidc_session_id})
    owned_configuration = configuration._ConfigurationCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(generation)
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    # The original source structures use tuples, including roots and primary
    # proof inventories. Preserve them with the real query reader's copier.
    from serverware import authority_query_reads as reads

    owned_source = reads._CopyBudget(work).copy({
        "business": business_before_roots, "authorization": authorization_before_roots,
        "selected": selected_rows, "proofs": before_proofs})
    held_reads = tuple(reads._copy_read(record, work) for record in query_reads)
    rows = source._verify_on_work(
        registration_challenge_id=owned_inputs["challengeId"],
        published_publication_id=owned_inputs["publicationId"], oidc_session_id=owned_inputs["sessionId"],
        business_before_roots=owned_source["business"],
        authorization_before_roots=owned_source["authorization"],
        selected_rows=owned_source["selected"], before_proofs=owned_source["proofs"],
        query_reads=held_reads, work=work)
    work.prepare_copy(owned_inputs["transports"])
    return _produce_on_configuration(payload=owned_configuration, configuration_digest=digest,
        generation=owned_generation, runtime_role_identities=owned_runtime,
        evidence_private_key=signer, evidence_signer_identity=owned_inputs["signerIdentity"],
        client_data_json=original_client, attestation_object=original_attestation,
        credential_id=owned_inputs["credentialId"], transports=tuple(owned_inputs["transports"]),
        challenge_row=rows.challenge_row, user_id=owned_inputs["userId"], label=owned_inputs["label"],
        expected_authorization=owned_inputs["authorization"], high_water_row=rows.high_water_row,
        published_row=rows.published_row, oidc_session_row=rows.oidc_session_row,
        sibling_challenge_ids=owned_inputs["siblings"], verified_at=instant, work=work)


def _produce_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, evidence_private_key, evidence_signer_identity,
        client_data_json, attestation_object, credential_id, transports,
        challenge_row, user_id, label, expected_authorization, high_water_row,
        published_row, oidc_session_row, sibling_challenge_ids, verified_at, work):
    """Return actual envelope, finalization arguments, evidence request and inputs.

    These four ordinary values supply the existing preparation workflow; they
    are neither a successful-proof carrier nor authority to execute or persist.
    There is deliberately no caller scope, trust-root list, signer public key,
    RP/origin override, purpose selector or maximum-age override.
    """
    ledger = evidence.capture._SharedLedger(work)
    original_client, original_attestation = client_data_json, attestation_object
    for raw, maximum in ((original_client, production.attestation.MAX_CLIENT_DATA_JSON_BYTES),
            (original_attestation, production.attestation.MAX_ATTESTATION_OBJECT_BYTES)):
        if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
            raise WebAuthnRegistrationSigningError("registration signing requires bounded original bytes")
    if (type(transports) is not tuple or len(transports) > 16
            or type(sibling_challenge_ids) is not list
            or len(sibling_challenge_ids) > production.registration.MAX_SIBLINGS):
        raise WebAuthnRegistrationSigningError("registration signing original inventories exceed their bounds")
    signer, instant, digest = evidence_private_key, verified_at, configuration_digest
    if not isinstance(signer, evidence.keys.Ed25519PrivateKey):
        raise WebAuthnRegistrationSigningError("independent evidence signer must be Ed25519")
    production.registration._digest(digest)
    production.registration._integer(production.registration._now(instant), "original registration time", 1)
    work.prepare_copy(transports)
    owned_inputs = evidence.capture._JSONCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit({
            "credentialId": credential_id, "transports": list(transports),
            "challenge": challenge_row, "userId": user_id, "label": label,
            "authorization": expected_authorization, "highWater": high_water_row,
            "published": published_row, "session": oidc_session_row,
            "siblings": sibling_challenge_ids, "signerIdentity": evidence_signer_identity})
    # Capture every configuration/generation/runtime graph before asking the
    # genuine mapper to perform its native commitment/key work. Later callbacks
    # never reopen the original caller containers.
    owned_configuration = configuration._ConfigurationCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(generation)
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    evidence._identity(owned_inputs["signerIdentity"])
    captured, launch = configuration._capture_configuration_on_work(
        payload=owned_configuration, configuration_digest=digest,
        generation=owned_generation, work=work)
    configuration._capture_runtime_role_identities_on_work(
        runtime_role_identities=owned_runtime, owned_payload=captured,
        configuration_digest=digest, launch=launch, work=work)
    roles = captured["roles"]
    if type(roles) is not dict or type(roles.get("planner")) is not dict:
        raise WebAuthnRegistrationSigningError("registration signing requires its actual enabled planner policy")
    evidence.plan.contract._literal(roles["planner"]["processMode"], "policy-authority-planner")
    read_configuration._require_enabled_operation(
        roles["planner"], "webauthn.registration.evidence.admit", work)
    if policy.FIELD not in captured:
        raise WebAuthnRegistrationSigningError("registration evidence signing has no explicit purpose policy")
    purposes, public_keys = policy._validate_policy_on_work(
        captured[policy.FIELD], webauthn=captured["webauthn"], work=work)
    selected = purposes["registration"]
    if selected is None:
        raise WebAuthnRegistrationSigningError("registration evidence signing is disabled")
    # Every scalar and identity comes from the explicit registration purpose,
    # never the core cohort's verifier or planner signing configuration.
    expected_identity = selected["signerIdentity"]
    public_key = public_keys["registration"]
    signer_spki = selected["signingSpkiDigest"]
    rp_id, origin, maximum_age_ns = selected["rpId"], selected["origin"], selected["maximumAgeNs"]
    production.registration._same(owned_inputs["signerIdentity"], expected_identity,
        work, "actual independent evidence signer differs from admitted registration purpose")
    evidence.keys._pair_on_work(signer, public_key, work)
    work.prepare_copy(owned_inputs["transports"])
    return production._produce_from_rows_on_work(
        client_data_json=original_client, attestation_object=original_attestation,
        credential_id=owned_inputs["credentialId"], transports=tuple(owned_inputs["transports"]),
        challenge_row=owned_inputs["challenge"], user_id=owned_inputs["userId"], label=owned_inputs["label"],
        expected_authorization=owned_inputs["authorization"], high_water_row=owned_inputs["highWater"],
        published_row=owned_inputs["published"], oidc_session_row=owned_inputs["session"],
        sibling_challenge_ids=owned_inputs["siblings"], rp_id=rp_id, origin=origin, verified_at=instant,
        private_key=signer, public_key=public_key, signer_identity=expected_identity,
        signer_spki_digest=signer_spki, maximum_age_ns=maximum_age_ns, work=work)
