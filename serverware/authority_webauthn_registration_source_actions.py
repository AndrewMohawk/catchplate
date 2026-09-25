"""Authenticate fixed live registration source reads and replay original proofs.

The actual verifier observes independent roots and admits selector/enrollment
provenance before request signing. The planner authenticates that request before
opening its configured read-only owner. It signs only after actual acquisition
and original proof replay; the verifier authenticates the returned bytes before
decoding and repeating their real memberships and bounded database-time joins.
Transport role keys are not registration-evidence signing authority. No caller
proof result, clock renewal, root reservation, mutation, custody or retry exists.
All capture, signatures, I/O guards and proof work share the original allowance.
"""
from __future__ import annotations

from serverware import authority_query_reads as reads
from serverware import authority_revocation_configuration as measured
from serverware import authority_webauthn_evidence_configuration as read_configuration
from serverware import authority_webauthn_evidence_custody_configuration as configuration
from serverware import authority_webauthn_evidence_custody_wire as wire
from serverware import authority_webauthn_evidence_planning as planning
from serverware import authority_webauthn_registration_source_request as request_wire
from serverware import authority_webauthn_registration_source_response as response_wire
from serverware import authority_webauthn_registration_source_transport as transport
from serverware import authority_webauthn_registration_source_wire as source_wire


evidence = wire.evidence


class WebAuthnRegistrationSourceActionError(ValueError):
    pass


def _fresh(timing, window, configured, work):
    return wire._fresh_on_work(timing, window=window,
        maximum_age_ns=configured.maximum_control_age_ns,
        maximum_clock_skew_ns=configured.pins[9], work=work)


def _produce_request_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, registration_challenge_id, published_publication_id,
        oidc_session_id, business_before_roots, authorization_before_roots,
        deadline_epoch_ns, verifier_private_key, work):
    signer = verifier_private_key
    if not isinstance(signer, wire.retention.plan.Ed25519PrivateKey):
        raise WebAuthnRegistrationSourceActionError("registration source request requires the actual verifier key")
    owned = reads._CopyBudget(work).copy({
        "challenge": registration_challenge_id, "publication": published_publication_id,
        "session": oidc_session_id, "business": business_before_roots,
        "authorization": authorization_before_roots, "deadline": deadline_epoch_ns})
    configured = configuration._capture_on_work(purpose="registration", payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    return request_wire._produce_on_work(registration_challenge_id=owned["challenge"],
        published_publication_id=owned["publication"], oidc_session_id=owned["session"],
        business_before_roots=owned["business"], authorization_before_roots=owned["authorization"],
        deadline_epoch_ns=owned["deadline"], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_private_key=signer, verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)


def _produce_response_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, control_bytes, context_bytes, read_dsn, planner_private_key, work):
    originals = transport._validate_request(control_bytes=control_bytes, context_bytes=context_bytes)
    signer, dsn, digest = planner_private_key, read_dsn, configuration_digest
    if not isinstance(signer, wire.retention.plan.Ed25519PrivateKey):
        raise WebAuthnRegistrationSourceActionError("registration source response requires the actual planner key")
    if (type(dsn) is not str or not 1 <= len(dsn) <= 65536
            or any(character in dsn for character in ("\x00", "\r", "\n"))):
        raise WebAuthnRegistrationSourceActionError("registration source response requires one protected read DSN")
    # Both genuine configured owners consume this same held graph. Native key
    # callbacks cannot cause the second mapper to reopen caller configuration.
    ledger = evidence.capture._SharedLedger(work)
    evidence.plan.contract._digest(digest)
    if type(payload) is not dict or type(generation) is not dict:
        raise WebAuthnRegistrationSourceActionError("registration source configuration is not closed data")
    measured.capability.shape._bounded_object(generation, 24, "registration source launch context")
    owned_payload = measured._ConfigurationCapture(
        ledger, maximum_bytes=wire.authority.MAX_REQUEST_BYTES).visit(payload)
    owned_runtime = evidence.capture._JSONCapture(ledger, maximum_bytes=8192).visit(runtime_role_identities)
    held_generation = evidence.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in measured._GENERATION_FIELDS})
    configured = configuration._capture_on_work(purpose="registration", payload=owned_payload,
        configuration_digest=digest, generation=held_generation,
        runtime_role_identities=owned_runtime, work=work)
    verified = request_wire._verify_on_work(control_bytes=originals[0], context_bytes=originals[1],
        pins=configured.pins, generation_sequence=configured.generation_sequence,
        generation_digest=configured.generation_digest, verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    context, window = verified.context, verified.window
    issued, expires = verified.issued_at_epoch_ns, verified.expires_at_epoch_ns
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    _fresh(timing, window, configured, work)
    owner = read_configuration._registration_planner_from_configuration_on_work(
        payload=owned_payload, configuration_digest=digest, generation=held_generation,
        runtime_role_identities=owned_runtime, read_dsn=dsn, work=work)
    _fresh(timing, window, configured, work)
    work.prepare_copy(context["businessBeforeRoots"])
    work.prepare_copy(context["authorizationBeforeRoots"])
    observed = planning.EvidenceAdmissionPlanner.acquire_registration_source(owner,
        registration_challenge_id=context["registrationChallengeId"],
        published_publication_id=context["publishedPublicationId"], oidc_session_id=context["oidcSessionId"],
        business_before_roots=tuple(context["businessBeforeRoots"]),
        authorization_before_roots=tuple(context["authorizationBeforeRoots"]),
        now_epoch_ns=issued, deadline_epoch_ns=expires, work=work)
    _fresh(timing, window, configured, work)
    source_bytes = source_wire._encode_on_work(
        business_before_roots=observed.business_before_roots,
        authorization_before_roots=observed.authorization_before_roots,
        selected_rows=observed.selected_rows, before_proofs=observed.before_proofs,
        query_reads=observed.query_reads, database_now=observed.database_now, work=work)
    source_wire._verify_on_work(source_bytes=source_bytes, request_context=context,
        request_issued_at_epoch_ns=issued, request_expires_at_epoch_ns=expires,
        maximum_clock_skew_ns=configured.pins[9], work=work)
    _fresh(timing, window, configured, work)
    response = response_wire._produce_on_work(request_control_bytes=originals[0], source_bytes=source_bytes,
        pins=configured.pins, generation_sequence=configured.generation_sequence,
        generation_digest=configured.generation_digest, planner_private_key=signer,
        verifier_public_key=configured.verifier_public_key, request_issued_at_epoch_ns=issued,
        request_expires_at_epoch_ns=expires, request_window=window,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    _fresh(timing, window, configured, work)
    return transport._validate_response(response, source_bytes)


def _request_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, control_bytes, context_bytes, work):
    originals = transport._validate_request(control_bytes=control_bytes, context_bytes=context_bytes)
    configured = configuration._capture_on_work(purpose="registration", payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    verified = request_wire._verify_on_work(control_bytes=originals[0], context_bytes=originals[1],
        pins=configured.pins, generation_sequence=configured.generation_sequence,
        generation_digest=configured.generation_digest, verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    context, window = verified.context, verified.window
    issued, expires = verified.issued_at_epoch_ns, verified.expires_at_epoch_ns
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    endpoint = configured.planner_endpoint
    _fresh(timing, window, configured, work)
    received = evidence.production._callback(work, lambda: transport._socket_request(endpoint,
        control_bytes=originals[0], context_bytes=originals[1]))
    if type(received) is not tuple or len(received) != 2:
        raise WebAuthnRegistrationSourceActionError("registration source response is not its exact raw pair")
    response = transport._validate_response(*received)
    _fresh(timing, window, configured, work)
    # The response signature and original-request/full-source byte commitments
    # must pass before any returned row, root or database cutoff is decoded.
    response_wire._verify_on_work(control_bytes=response[0], request_control_bytes=originals[0],
        source_bytes=response[1], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key, request_issued_at_epoch_ns=issued,
        request_expires_at_epoch_ns=expires, request_window=window,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    source_wire._verify_on_work(source_bytes=response[1], request_context=context,
        request_issued_at_epoch_ns=issued, request_expires_at_epoch_ns=expires,
        maximum_clock_skew_ns=configured.pins[9], work=work)
    _fresh(timing, window, configured, work)
    return response
