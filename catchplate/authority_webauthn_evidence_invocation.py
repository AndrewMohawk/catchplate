"""Assemble the two fixed evidence-admission invocations from original inputs.

The caller must independently admit the ceremony/installation inputs, signed
evidence provenance, authorization and selected publication/session rows.
This module owns those inputs, derives their source request commitments and
retains their exact originals. It does not authenticate the supplied evidence,
admit rows or trust roots, sample time, select credentials or grant authority.
The actual configured preparation and complete original-input replay remain
mandatory; neither returned object is a successful verification carrier.

Both constructors return ordinary ``(request, inputs_bytes)`` on the supplied
work. They accept no caller request, evidence digest, operation ID or alternate
operation, and perform no database, network, custody-forward or signing work.
"""
from __future__ import annotations

from catchplate import authority_request_commitment as commitment
from catchplate import authority_transition_webauthn_installation_admission as installation
from catchplate import authority_transition_webauthn_registration_admission as registration
from catchplate import authority_webauthn_evidence_plan_contract as contract
from catchplate import authority_webauthn_installation_inputs as installation_inputs
from catchplate import authority_webauthn_registration_inputs as registration_inputs


evidence, authority = registration.evidence, registration.authority
production = registration_inputs.production
ceremony = production.registration
completion = installation.completion


class WebAuthnEvidenceInvocationError(ValueError):
    pass


def _request_on_work(operation, arguments, work):
    """Use the actual source intent and request/operation commitment bodies."""
    if type(operation) is not str or operation not in (
            registration.OPERATION, installation.OPERATION):
        raise WebAuthnEvidenceInvocationError("evidence invocation operation is not source fixed")
    arguments["businessIntent"] = authority._synthesize_business_intent(
        operation, arguments, work=work)
    if operation == registration.OPERATION:
        registration._arguments(arguments, work)
    else:
        installation._arguments(arguments, work)
    spec = authority.operation_spec(operation)
    # The shared commitment excludes these two outputs. No placeholder is
    # exposed or submitted: both are filled from the actual computation below.
    request = {"schema": contract.shape.TYPED_REQUEST_SCHEMA,
        "operation": operation, "operationId": None, "requestDigest": None,
        "handler": spec["handler"],
        "operationManifestDigest": authority.OPERATION_MANIFEST_DIGEST,
        "arguments": arguments}
    digest = commitment._typed_request_digest(request, work=work)
    work.prepare_utf8(operation)
    work.prepare_utf8(digest)
    work.charge(hashes=1)
    identifier = commitment.operation_id(operation, digest)
    request["requestDigest"], request["operationId"] = digest, identifier
    owned = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work),
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(request)
    contract._request(owned, operation, spec)
    return owned


def _registration_on_work(*, envelope_bytes, client_data_json, attestation_object,
        credential_id, transports, scope, verification_context,
        expected_authorization, published_row, oidc_session_row, work):
    """Assemble registration admission without claiming the inputs' provenance.

    ``scope`` and ``verification_context`` are the genuine original core types.
    ``published_row`` and the optional OIDC row must already be independently
    admitted. Challenge and session identifiers are joined to the original
    scope/authorization; the publication identifier comes from that held row.
    Current row membership, authorization and all signatures are checked again
    by the real downstream acquisition/replay, not by this assembler.
    """
    ledger = evidence.capture._SharedLedger(work)
    originals = (
        registration_inputs._raw(envelope_bytes, 2, evidence.MAX_EVIDENCE_BYTES),
        registration_inputs._raw(client_data_json, 1,
            production.attestation.MAX_CLIENT_DATA_JSON_BYTES),
        registration_inputs._raw(attestation_object, 1,
            production.attestation.MAX_ATTESTATION_OBJECT_BYTES))
    if type(transports) is not tuple or len(transports) > 16:
        raise WebAuthnEvidenceInvocationError("registration transports are not an exact bounded tuple")
    scope_fields, context_fields, roots = production._hold_context(
        scope, verification_context, work)
    work.prepare_copy(transports)
    owned = evidence.capture._JSONCapture(ledger).visit({
        "authorization": expected_authorization, "published": published_row,
        "session": oidc_session_row, "credentialId": credential_id,
        "transports": list(transports)})
    authorization, published, session = (
        owned["authorization"], owned["published"], owned["session"])
    ceremony._closed(published, production._PUBLICATION_FIELDS,
        "invocation admitted publication row")
    if type(authorization) is not dict:
        raise WebAuthnEvidenceInvocationError("registration authorization is not an exact object")
    mode = authorization.get("mode")
    if type(mode) is not str or mode not in ceremony._MODES:
        raise WebAuthnEvidenceInvocationError("registration authorization mode is not source fixed")
    ceremony._digest(authorization.get("payload_digest"))
    challenge_id, user_id, authorization_bytes = (
        scope_fields[0], scope_fields[2], scope_fields[4])
    publication_id = published["id"]
    ceremony._text(challenge_id, "invocation challenge ID", 4096, work)
    ceremony._text(publication_id, "invocation publication ID", 4096, work)
    ceremony._same((published["scope"], published["status"]),
        ("global", "published"), work, "invocation published predecessor")
    session_id = None
    if mode == "oidc-session-first-enrollment":
        ceremony._closed(session, production._SESSION_FIELDS,
            "invocation admitted OIDC session row")
        session_id = session["id"]
        ceremony._text(session_id, "invocation OIDC session ID", 4096, work)
        ceremony._same((session_id, session["user_id"], authorization.get("user_id")),
            (authorization.get("session_id"), user_id, user_id), work,
            "invocation original OIDC authorization")
    elif session is not None:
        raise WebAuthnEvidenceInvocationError("non-OIDC registration cannot select an OIDC session")

    # All caller graphs, exact original byte references, core members and
    # selected IDs are held before any real constructor/codec/hash callback.
    # Reconstruct the actual core types from those members, never revisit a
    # caller-owned scope/context after the first native callback.
    held_scope = production.attestation.CeremonyScope(*scope_fields, _work=work)
    held_roots = tuple(production.attestation.TrustRootSnapshot(*fields, _work=work)
        for fields in roots)
    held_context = production.attestation.VerificationContext(
        *context_fields, held_roots, _work=work)
    canonical_authorization = ceremony._wire(authorization, work)
    work.charge(input_bytes=len(canonical_authorization) + len(authorization_bytes))
    if canonical_authorization != authorization_bytes:
        raise WebAuthnEvidenceInvocationError("registration authorization differs from the original ceremony")
    work.prepare_copy(owned["transports"])
    inputs_bytes = registration_inputs._encode_on_work(envelope_bytes=originals[0],
        client_data_json=originals[1], attestation_object=originals[2],
        credential_id=owned["credentialId"], transports=tuple(owned["transports"]),
        scope=held_scope, verification_context=held_context,
        expected_authorization=authorization, work=work)
    digest = evidence._evidence_digest_on_work(originals[0], work)
    request = _request_on_work(registration.OPERATION, {
        "evidence_digest": digest, "registration_challenge_id": challenge_id,
        "published_publication_id": publication_id, "oidc_session_id": session_id}, work)
    return request, inputs_bytes


def _installation_on_work(*, installation_envelope_bytes, installed_bundle_bytes,
        installed_state_bytes, observed_at, expected_committed_stage,
        publication_row, work):
    """Assemble installation admission from originals and an admitted stage row.

    The committed-stage graph contains commitments, not a publication ID.
    The independently admitted pending publication row supplies that selector;
    genuine downstream installation replay must still prove their association,
    installer signature, signed installation observation and original time.
    """
    ledger = evidence.capture._SharedLedger(work)
    originals = (installation_envelope_bytes, installed_bundle_bytes, installed_state_bytes)
    for original, (_, maximum) in zip(originals, installation_inputs._RAW_LIMITS):
        registration_inputs._raw(original, 2, maximum)
    completion._now(observed_at)
    held_observed_at = observed_at
    owned = evidence.capture._JSONCapture(ledger).visit({
        "stage": expected_committed_stage, "publication": publication_row})
    stage, publication = owned["stage"], owned["publication"]
    installation_inputs._stage(stage)
    completion._object(publication, completion._PUBLICATION_FIELDS,
        "invocation admitted installation publication row")
    publication_id = publication["id"]
    work.prepare_utf8(publication_id)
    completion._text(publication_id, "invocation installation publication ID")
    ceremony._same((publication["scope"], publication["status"], publication["published_at"]),
        ("global", "pending", None), work, "invocation pending installation publication")
    inputs_bytes = installation_inputs._encode_on_work(
        installation_envelope_bytes=originals[0], installed_bundle_bytes=originals[1],
        installed_state_bytes=originals[2], observed_at=held_observed_at,
        expected_committed_stage=stage, work=work)
    digest = evidence._evidence_digest_on_work(originals[0], work)
    request = _request_on_work(installation.OPERATION, {
        "evidence_digest": digest, "publication_id": publication_id}, work)
    return request, inputs_bytes
