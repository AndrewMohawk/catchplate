"""Genuine registration cryptography composed with original evidence signing.

The caller independently admits the exact ceremony, selected challenge and
authorization, published high-water and complete trust-root snapshot. This
worker does not prove row selection, pending-publication absence, unused global
credential history, enrollment permission, signer configuration or currentness.
It never accepts a successful attestation DTO: the real shared core parses and
verifies the original bytes in this invocation before deriving signed claims.

Source-visible ownership, encoding and SHA work share the original meter.
Bounded native JSON/CBOR/X509/EC/RSA internals remain the core's explicit native
boundary, not a whole-crypto CPU/memory guarantee. There is no replacement work
allowance, clock, database, filesystem, registry activation or registration
grant. The original envelope still needs genuine v2 custody and the successor
transition's independent row/proof/signature admission before any mutation.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone

from serverware import authority_transition_webauthn_registration as registration
from serverware import webauthn_attestation_core as attestation


authority, evidence, trust = registration.authority, registration.evidence, registration.trust
capture, core = registration.capture, registration.core
_HIGH_FIELDS = frozenset({"authority_scope", "rollback_epoch", "publication_sequence",
    "publication_digest", "metadata_blob_digest", "revocation_set_digest",
    "witness_receipt_digest", "witness_sequence", "updated_at_epoch_ns"})
_PUBLICATION_FIELDS = frozenset({"id", "scope", "previous_bundle_digest", "bundle_digest",
    "sequence", "rollback_epoch", "signing_key_id", "bundle_json", "payload_digest",
    "actor_id", "withdrawn_credential_ids_json", "audit_event_json", "status", "attempts",
    "last_error", "created_at", "published_at"})
_SESSION_FIELDS = frozenset({"id", "token_digest", "oidc_token_digest", "user_id",
    "roles_json", "status", "provider_expires_at", "expires_at", "pending_expires_at",
    "created_at", "updated_at", "activated_at", "revoked_at", "bound_webauthn_credential_id",
    "activation_trust_bundle_digest", "activation_trust_bundle_sequence",
    "activation_authenticator_class", "revocation_reason"})


class WebAuthnRegistrationProductionError(ValueError):
    pass


def _fail(message):
    raise WebAuthnRegistrationProductionError(message)


def _hold_context(scope, context, work):
    """Hold exact immutable members before the constructors' native callbacks."""
    if type(scope) is not attestation.CeremonyScope or type(context) is not attestation.VerificationContext:
        _fail("registration production needs exact independently admitted core contexts")
    if (type(context.verified_at) is not datetime or context.verified_at.tzinfo is not timezone.utc
            or type(context.trust_roots) is not tuple
            or len(context.trust_roots) > attestation.MAX_TRUST_ROOTS):
        _fail("registration production context time or trust inventory is invalid")
    scope_fields = (scope.challenge_id, scope.challenge, scope.user_id, scope.label, scope.authorization_json)
    context_fields = (context.rp_id, context.origin, context.verified_at)
    roots, total = [], 0
    for root in context.trust_roots:
        if (type(root) is not attestation.TrustRootSnapshot
                or type(root.certificate_der) is not bytes
                or not 1 <= len(root.certificate_der) <= attestation.MAX_ATTESTATION_CERTIFICATE_BYTES
                or type(root.aaguids) is not frozenset or len(root.aaguids) > 1024):
            _fail("registration production root snapshot is not bounded and exact")
        total += len(root.certificate_der)
        if total > attestation.MAX_TRUST_SNAPSHOT_BYTES:
            _fail("registration production trust snapshot exceeds its existing source bound")
        # All held members are immutable exact scalar values. Constructors
        # below perform their real semantic validation, hashing and copying.
        metadata = (root.certificate_sha256, root.authenticator_class, root.bundle_digest,
            root.bundle_sequence, root.bundle_rollback_epoch)
        if (any(type(value) is not str for value in root.aaguids)
                or type(metadata[0]) is not str
                or any(value is not None and type(value) is not str for value in metadata[1:3])
                or any(value is not None and type(value) is not int for value in metadata[3:])):
            _fail("registration production root members are not immutable source scalars")
        work.charge(input_bytes=len(root.certificate_der), json_nodes=1)
        roots.append((root.certificate_der, metadata[0], metadata[1], root.aaguids,
            metadata[2], metadata[3], metadata[4]))
    if (any(type(value) is not str for value in scope_fields[:4])
            or type(scope_fields[4]) is not bytes
            or any(type(value) is not str for value in context_fields[:2])):
        _fail("registration production ceremony members are not immutable source scalars")
    return scope_fields, context_fields, tuple(roots)


def _admitted_rows(owned, scope, context, maximum_age_ns, work):
    """Check bindings to supplied admitted rows, never claim their admission."""
    challenge, high, published = owned["challenge"], owned["high"], owned["published"]
    registration._closed(challenge, registration._CHALLENGE_FIELDS, "producer challenge row")
    registration._closed(high, _HIGH_FIELDS, "producer high-water row")
    registration._closed(published, _PUBLICATION_FIELDS, "producer publication row")
    now_ns = registration._now(context.verified_at)
    registration._integer(maximum_age_ns, "producer evidence lifetime", 1, authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    registration._same((challenge["id"], challenge["challenge"], challenge["challenge_type"],
        challenge["user_id"], challenge["approval_request_id"], challenge["used_at"]),
        (scope.challenge_id, scope.challenge, "registration", scope.user_id, None, None), work,
        "producer admitted challenge scope")
    challenge_expiry = registration._now(registration._utc(challenge["expires_at"], "challenge expiry", work))
    expires = min(now_ns + maximum_age_ns, challenge_expiry)
    payload = registration._stored_json(challenge["payload_json"], work)
    if type(payload) is not dict:
        _fail("registration producer challenge payload is not an object")
    registration._same((payload.get("type"), payload.get("user_id"), payload.get("label")),
        ("registration", scope.user_id, scope.label), work, "producer challenge payload")
    authorization = payload.get("authorization")
    if type(authorization) is not dict:
        _fail("registration producer challenge has no enrollment authorization")
    registration._same(authorization, owned["authorization"], work, "independently admitted authorization")
    mode = authorization.get("mode")
    if type(mode) is not str or mode not in registration._MODES:
        _fail("registration producer authorization mode is unsupported")
    registration._digest(authorization.get("payload_digest"))
    authorization_bytes = registration._wire(authorization, work)
    work.charge(input_bytes=len(authorization_bytes) + len(scope.authorization_json))
    if authorization_bytes != scope.authorization_json:
        _fail("registration producer ceremony authorization differs from the admitted row")
    document = trust.high_water_document(rollback_epoch=high["rollback_epoch"],
        sequence=high["publication_sequence"], publication_digest=high["publication_digest"],
        metadata_blob_digest=high["metadata_blob_digest"], revocation_set_digest=high["revocation_set_digest"],
        witness_receipt_digest=high["witness_receipt_digest"], witness_sequence=high["witness_sequence"])
    registration._same(high["authority_scope"], trust.AUTHORITY_SCOPE, work, "producer trust scope")
    for actual, wanted in ((published["scope"], "global"), (published["status"], "published"),
            (published["bundle_digest"], high["publication_digest"]),
            (published["payload_digest"], high["metadata_blob_digest"]),
            (published["sequence"], high["publication_sequence"]),
            (published["rollback_epoch"], high["rollback_epoch"])):
        if type(actual) is not type(wanted):
            _fail("registration producer publication predecessor type differs")
        registration._same(actual, wanted, work, "producer published predecessor")
    session_id, session = None, owned["session"]
    if mode == "oidc-session-first-enrollment":
        registration._closed(authorization, frozenset({"mode", "session_id", "user_id",
            "pending_expires_at", "payload_digest", "existing_credential_count"}), "producer OIDC authorization")
        registration._integer(authorization["existing_credential_count"], "OIDC historical count", 0, 0)
        registration._closed(session, _SESSION_FIELDS, "producer OIDC session")
        session_id = session["id"]
        registration._same((session_id, session["user_id"], session["status"], session["pending_expires_at"],
            session["activated_at"], session["revoked_at"], session["bound_webauthn_credential_id"]),
            (authorization["session_id"], scope.user_id, "pending_webauthn", authorization["pending_expires_at"],
             None, None, None), work, "producer live OIDC enrollment")
        registration._same(authorization["user_id"], scope.user_id, work, "producer OIDC authorization user")
        for field in ("expires_at", "pending_expires_at"):
            expires = min(expires, registration._now(registration._utc(session[field], "OIDC expiry", work)))
    elif session is not None or owned["siblings"]:
        _fail("ordinary registration cannot acquire OIDC session or sibling authority")
    registration._integer(expires, "producer evidence expiry", 1)
    if expires <= now_ns:
        _fail("registration producer challenge or authorization is expired")
    return authorization, document, now_ns, expires, session_id


def _prepare_result(claims, arguments, identity, signer_pin, now_ns, expires, work):
    """Prepare only sizing scalars, never a successful evidence placeholder.

    Ed25519 signature/base64/digest text has fixed width. The real public
    business-intent normalizer runs before signing; its two signature-dependent
    scalar leaves are replaced by actual originals afterward. Every post-sign
    codec/hash operation below is prepaid here on the same meter.
    """
    placeholder = {"schema": evidence.SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": "registration-attestation", "signerIdentity": identity,
        "signerSpkiDigest": signer_pin, "issuedAtEpochNs": now_ns,
        "expiresAtEpochNs": expires, "claims": claims, "signatureBase64Url": "A" * 86}
    evidence._shape(placeholder)
    size, nodes = work.measure(placeholder)
    if size > evidence.MAX_EVIDENCE_BYTES or nodes > evidence.MAX_EVIDENCE_NODES:
        _fail("registration evidence exceeds its source output bounds")
    padded = 4 * ((size + 2) // 3)
    encoded_size = padded - ((3 - size % 3) % 3)
    work.charge(input_bytes=encoded_size + 71)
    arguments["attestation_envelope_base64url"] = "A" * encoded_size
    arguments["attestation_evidence_digest"] = "sha256:" + "0" * 64
    arguments["businessIntent"] = authority._synthesize_business_intent(registration.OPERATION, arguments, work=work)
    # This is source argument validation, not envelope signature validation.
    # No placeholder leaves the worker or reaches evidence custody.
    registration._arguments(arguments, work)
    final_size, _ = work.measure(arguments)
    if final_size > authority.MAX_REQUEST_BYTES:
        _fail("registration final arguments exceed the existing request bound")
    work.prepare_utf8(evidence.IDENTITY_DOMAIN)
    work.charge(hashes=1, input_bytes=9 + size)
    # Actual invocation codec recipe: input, padded output, translation,
    # strip and ASCII decode. No post-sign work allocation or refund.
    work.charge(input_bytes=size + 3 * padded + encoded_size)
    return size


def _produce_on_work(*, client_data_json, attestation_object, credential_id, transports,
        scope, verification_context, challenge_row, expected_authorization, high_water_row,
        published_row, oidc_session_row, sibling_challenge_ids, private_key, public_key,
        signer_identity, signer_spki_digest, maximum_age_ns, work):
    """Return (actual signed original envelope, final registration arguments)."""
    ledger = capture._SharedLedger(work)
    for raw, maximum in ((client_data_json, attestation.MAX_CLIENT_DATA_JSON_BYTES),
            (attestation_object, attestation.MAX_ATTESTATION_OBJECT_BYTES)):
        if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
            _fail("registration producer requires bounded exact original bytes")
    if type(transports) is not tuple or len(transports) > 16:
        _fail("registration producer transports are not a bounded exact tuple")
    if type(sibling_challenge_ids) is not list or len(sibling_challenge_ids) > registration.MAX_SIBLINGS:
        _fail("registration producer sibling inventory is not a bounded exact list")
    scope_fields, context_fields, roots = _hold_context(scope, verification_context, work)
    work.prepare_copy(transports)
    owned = capture._JSONCapture(ledger).visit({"challenge": challenge_row,
        "authorization": expected_authorization, "high": high_water_row, "published": published_row,
        "session": oidc_session_row, "siblings": sibling_challenge_ids, "identity": signer_identity,
        "credentialId": credential_id, "transports": list(transports)})
    evidence._identity(owned["identity"])
    registration._digest(signer_spki_digest)
    # No caller graph is read after the first native parsing/key callback.
    scope = attestation.CeremonyScope(*scope_fields, _work=work)
    owned_roots = tuple(attestation.TrustRootSnapshot(*fields, _work=work) for fields in roots)
    context = attestation.VerificationContext(*context_fields, owned_roots, _work=work)
    authorization, high, now_ns, expires, session_id = _admitted_rows(
        owned, scope, context, maximum_age_ns, work)
    work.prepare_copy(owned["transports"])
    parsed = attestation.parse_registration_data(client_data_json, attestation_object,
        owned["credentialId"], scope=scope, rp_id=context.rp_id, origin=context.origin,
        transports=tuple(owned["transports"]), _work=work)
    result = attestation.verify_registration_attestation(parsed, context, _work=work)
    verified = result.attestation
    if verified.trusted:
        registration._same((verified.trust_bundle_digest, verified.trust_bundle_sequence),
            (high["publicationDigest"], high["sequence"]), work, "producer derived trusted generation")
    work.prepare_copy(verified.trust_path)
    work.prepare_copy(result.transports)
    credential = {"credential_id": result.credential_id, "user_id": scope.user_id, "label": scope.label,
        "public_key_cose": registration.invocation._encode(result.public_key_cose, work),
        "sign_count": result.sign_count, "aaguid": result.aaguid,
        "authenticator_class": result.authenticator_class, "attestation_fmt": verified.fmt,
        "attestation_trusted": verified.trusted, "attestation_trust_path": list(verified.trust_path),
        "attestation_leaf_sha256": verified.leaf_sha256, "attestation_root_sha256": verified.root_sha256,
        "attestation_trust_bundle_digest": verified.trust_bundle_digest,
        "attestation_trust_bundle_sequence": verified.trust_bundle_sequence,
        "attestation_verified_at": verified.verified_at, "transports": list(result.transports),
        "user_verified": result.user_verified}
    intent = {"schema": registration.INTENT_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "operation": registration.OPERATION, "profile": registration.PROFILE,
        "challengeId": scope.challenge_id,
        "challengeRowDigest": registration._framed("serverware.policyAuthorityWebAuthnChallengeRow/v1", owned["challenge"], work),
        "userId": scope.user_id, "label": scope.label,
        "authorizationDigest": registration._framed("serverware.policyAuthorityWebAuthnRegistrationAuthorization/v2", authorization, work),
        "authorizationMode": authorization["mode"], "rpId": context.rp_id, "origin": context.origin,
        "clientDataDigest": result.client_data_sha256, "attestationObjectDigest": result.attestation_object_sha256,
        "trustHighWaterDigest": trust.high_water_digest(high, work=work)}
    claims = {"schema": registration.CLAIMS_SCHEMA,
        "intentDigest": registration._framed(registration.INTENT_DOMAIN, intent, work),
        "credential": credential, "trustHighWaterDigest": intent["trustHighWaterDigest"],
        "verifiedAtEpochNs": now_ns, "verifierMeasurementDigest": owned["identity"]["measurementDigest"],
        "verifierAttestationReceiptDigest": owned["identity"]["attestationReceiptDigest"]}
    arguments = {"semantic_intent": intent, "credential": credential, "challenge": scope.challenge,
        "verified_at_epoch_ns": now_ns, "oidc_session_id": session_id,
        "sibling_challenge_ids": owned["siblings"]}
    size = _prepare_result(claims, arguments, owned["identity"], signer_spki_digest, now_ns, expires, work)
    original = evidence._produce_on_work(purpose="registration-attestation", claims=claims,
        private_key=private_key, public_key=public_key, signer_identity=owned["identity"],
        signer_spki_digest=signer_spki_digest, issued_at_epoch_ns=now_ns,
        expires_at_epoch_ns=expires, work=work)
    if type(original) is not bytes or len(original) != size:
        _fail("registration evidence output differs from its prepared source shape")
    # Both real operations were reserved before the signer. Only immutable
    # fixed-width leaves change in the genuinely normalized business intent.
    encoded = base64.urlsafe_b64encode(original).rstrip(b"=").decode("ascii")
    digest = core.framed_digest(evidence.IDENTITY_DOMAIN, original)
    for target in (arguments, arguments["businessIntent"]["arguments"]):
        target["attestation_envelope_base64url"] = encoded
        target["attestation_evidence_digest"] = digest
    return original, arguments
