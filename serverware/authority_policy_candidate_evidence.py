"""Pure original-signature calculation shared by candidate intake owners.

The returned row is not an admission receipt or a writer capability. Production
callers must obtain every key/head/revocation input from the same authenticated
transaction that commits the corresponding typed transition. This module does
not open SQL, discover keys, authorize a caller, or manufacture native evidence.
"""
from collections.abc import Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_static_original(*, evidence_kind, envelope_json, envelope_digest,
        payload_json, payload_digest, signature_algorithm, signing_key_id,
        signature, signature_digest, record_binding, key, key_head, revocation,
        revocation_sequence, verified_at_epoch_ns):
    # Reuse the existing closed encodings and source-owned signature families;
    # importing the facade here does not acquire a database connection.
    from serverware import db

    def require(condition, message):
        if not condition:
            raise db.PolicyCandidateAuthorityError(message)

    domain = db._POLICY_AUTHORITY_EVIDENCE_DOMAINS.get(evidence_kind)
    require(domain is not None, "candidate evidence kind is not source selected")
    envelope_json, envelope_digest = db._candidate_authority_json(
        "signed envelope", envelope_json, envelope_digest)
    payload_json, payload_digest = db._candidate_authority_json(
        "signed payload", payload_json, payload_digest, maximum=8 * 1024 * 1024)
    db._candidate_authority_signature_fields({"signature_algorithm": signature_algorithm,
        "signing_key_id": signing_key_id, "signature": signature, "signature_digest": signature_digest})
    db._candidate_authority_digest("signing_key_id", signing_key_id)
    signature_bytes = db._candidate_authority_b64url("signature", signature, expected_bytes=64)
    require(db._candidate_authority_sha256(signature_bytes) == signature_digest,
        "candidate evidence signature original changed")
    envelope, payload = db.loads(envelope_json, None), db.loads(payload_json, None)
    kinds = {
        "generation_publication": "PolicyShadowGenerationPublication",
        "generation_runtime_attestation_verification": "PolicyShadowRuntimeAttestationVerification",
        "shadow_role_authorization": "PolicyShadowRoleAuthorization",
        "candidate_artifact": "PolicyCandidateArtifact", "canary_assignment": "PolicyShadowAssignment",
        "canary_state": "PolicyCanaryState", "runtime_attestation": "PolicyRuntimeAttestation",
        "runtime_role_revocation": "PolicyRuntimeRoleKeyRevocation", "compiler_analysis": "PolicyAuthorityAnalysis",
        "readiness": "PolicyActivationReadiness", "activation_state": "PolicyActivationState",
        "publication_receipt": "PolicyPublicationReceipt", "rollback_authority": "PolicyRollbackAuthority",
        "rollback_authority_revocation": "PolicyRollbackAuthorityRevocation",
        "audit_inclusion_receipt": "PolicyAuthorityAuditInclusion", "authority_genesis": "PolicyAuthorityGenesis",
    }
    require(type(envelope) is dict and set(envelope) == {"apiVersion", "kind", "canonicalProfile", "signatureDomain",
        "payload", "payloadSha256", "signatureAlgorithm", "signingKeyId", "signingKeySpkiSha256", "signature"},
        "candidate evidence envelope is not closed")
    require(envelope["apiVersion"] == envelope["signatureDomain"] == domain
        and envelope["kind"] == kinds[evidence_kind]
        and envelope["canonicalProfile"] == db._POLICY_AUTHORITY_CANONICAL_PROFILE
        and envelope["payload"] == payload and envelope["payloadSha256"] == payload_digest
        and envelope["signatureAlgorithm"] == signature_algorithm and envelope["signingKeyId"] == signing_key_id
        and envelope["signature"] == signature, "candidate evidence envelope binding changed")
    direct = evidence_kind in db._POLICY_SHADOW_DIRECT_STATIC_EVIDENCE_KINDS
    require(isinstance(record_binding, Mapping), "candidate record original is missing")
    bound = dict(record_binding)
    db._candidate_authority_json_value("signed record binding", bound)
    if direct:
        if evidence_kind == "canary_assignment":
            from serverware.authority_policy_canary_native_opening import assignment_fields
            expected_fields = assignment_fields(payload)
        else:
            expected_fields = db._POLICY_SHADOW_DIRECT_PAYLOAD_FIELDS[evidence_kind]
        require(type(payload) is dict and set(payload) == expected_fields,
            "candidate direct evidence payload is not closed")
        db._policy_shadow_assert_direct_record_binding(evidence_kind=evidence_kind, payload=payload, record_binding=bound)
        issued, expires = payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"]
    else:
        require(type(payload) is dict and set(payload) == {"issuedAtEpochNs", "expiresAtEpochNs", "record"}
            and payload["record"] == bound, "candidate evidence record differs from signed original")
        issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    for label, value in (("issued", issued), ("expires", expires), ("verified", verified_at_epoch_ns),
            ("revocation sequence", revocation_sequence)):
        require(type(value) is int and 0 <= value <= 9_223_372_036_854_775_807,
            "candidate evidence " + label + " is not an exact integer")
    require(0 <= issued < expires and verified_at_epoch_ns > 0, "candidate evidence interval is invalid")
    require(isinstance(key, Mapping) and isinstance(key_head, Mapping) and revocation is None,
        "candidate signing authority is absent or revoked")
    require(key["evidence_kind"] == key_head["evidence_kind"] == evidence_kind
        and key["signature_domain"] == domain and key["signing_key_id"] == signing_key_id
        and key["key_revision"] == key_head["head_key_revision"]
        and key["signing_key_id"] == key_head["head_signing_key_id"]
        and key["public_key_digest"] == key_head["head_public_key_digest"],
        "candidate signing authority is not the current exact head")
    raw_key = db._candidate_authority_b64url("trusted Ed25519 public key", key["public_key_base64url"], expected_bytes=32)
    public_key = Ed25519PublicKey.from_public_bytes(raw_key)
    spki = db._candidate_authority_sha256(public_key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    require(spki == key["public_key_digest"] == signing_key_id == envelope["signingKeySpkiSha256"],
        "candidate signing authority SPKI differs")
    for name in ("key_revision", "installed_at_epoch_ns", "not_before_epoch_ns", "not_after_epoch_ns",
            "max_clock_skew_ns", "max_evidence_age_ns"):
        require(type(key[name]) is int and 0 <= key[name] <= 9_223_372_036_854_775_807,
            "candidate signing authority integer is malformed")
    require(key["installed_at_epoch_ns"] <= verified_at_epoch_ns
        and key["not_before_epoch_ns"] <= verified_at_epoch_ns < key["not_after_epoch_ns"]
        and max(key["installed_at_epoch_ns"], key["not_before_epoch_ns"]) <= issued
        and expires <= key["not_after_epoch_ns"]
        and issued <= verified_at_epoch_ns + key["max_clock_skew_ns"]
        and verified_at_epoch_ns - issued <= key["max_evidence_age_ns"] and verified_at_epoch_ns < expires,
        "candidate signing authority or original evidence is not transaction-time current")
    message = b"\0".join((db._POLICY_AUTHORITY_SIGNATURE_FRAME, domain.encode("ascii"),
        db._POLICY_AUTHORITY_CANONICAL_PROFILE.encode("ascii"), payload_json.encode("ascii")))
    public_key.verify(signature_bytes, message)
    message_digest = db._candidate_authority_sha256(message)
    binding_digest = db._candidate_authority_sha256(b"\0".join((b"serverware.policyAuthorityRecordBinding/v1",
        domain.encode("ascii"), db.dumps(bound).encode("ascii"))))
    receipt = {"envelopeDigest": envelope_digest, "evidenceKind": evidence_kind, "expiresAtEpochNs": expires,
        "issuedAtEpochNs": issued, "payloadDigest": payload_digest, "publicKeySpkiSha256": spki,
        "recordBindingDigest": binding_digest, "signatureDigest": signature_digest,
        "signatureMessageDigest": message_digest, "signingKeyId": signing_key_id,
        "trustedKeyRevision": key["key_revision"], "trustedKeyInstalledAtEpochNs": key["installed_at_epoch_ns"],
        "trustedKeyRevocationSequence": revocation_sequence, "verifiedAtEpochNs": verified_at_epoch_ns}
    return {"verification_receipt_digest": db._candidate_authority_sha256(db.dumps(receipt).encode("ascii")),
        "evidence_kind": evidence_kind, "signing_key_id": signing_key_id, "signature_domain": domain,
        "public_key_digest": spki, "signature_algorithm": signature_algorithm, "signature": signature,
        "signature_digest": signature_digest, "record_binding_digest": binding_digest,
        "envelope_digest": envelope_digest, "payload_digest": payload_digest, "signature_message_digest": message_digest,
        "trusted_key_revision": key["key_revision"], "trusted_key_installed_at_epoch_ns": key["installed_at_epoch_ns"],
        "trusted_key_revocation_sequence": revocation_sequence, "issued_at_epoch_ns": issued,
        "expires_at_epoch_ns": expires, "verified_at_epoch_ns": verified_at_epoch_ns}
