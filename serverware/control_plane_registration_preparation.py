"""Private authenticated-app continuation to genuinely verified evidence.

The actual operator/OIDC handler must already have admitted its caller and the
original enrollment ceremony. An original-input carrier is not authentication,
row membership or a reservation. This continuation observes only a publication
selector, obtains the real source exchange and issues one grant for one signer
exchange. It neither retries nor falls back to legacy finalization.

Only the two existing cold owners supply runtime/configuration/key/endpoint
authority. One standard work allowance and one original live window cover this
composition. No caller-selected time, work, root, endpoint or session override
is accepted. The returned evidence-admission invocation is not registration
success: durable custody, current roots, complete OIDC sibling/history and
atomic business execution remain separate prerequisites.
"""
from __future__ import annotations

from datetime import datetime, timezone


class RegistrationPreparationError(ValueError):
    pass


def prepare_registration_evidence(originals):
    """Return actual (evidence envelope, evidence-admit request, input bytes)."""
    from serverware import control_plane_custody_client as custody_client
    from serverware import control_plane_custody_startup as custody_startup
    from serverware import control_plane_enrollment_startup as enrollment_startup
    from serverware import authority_webauthn_enrollment_issuer as issuer
    from serverware import db, webauthn
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    work = _ValidationWork(QueryReadValidationLimits())
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
    result = enrollment_startup._EnrollmentOwner.request_registration_evidence(
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
    return result
