"""Pure assigned-role signature calculation for the closed canary transaction.

Inputs are data, not authority. The batch owner obtains the complete key,
member and revocation originals from its authenticated transaction snapshot.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import authority_policy_canary as profile


def role_authorization(key):
    from catchplate import db
    value = {"assignmentEnvelopeDigest": key["assignment_envelope_digest"],
        "attestationReceiptEnvelopeDigest": key["attestation_receipt_envelope_digest"], "bootId": key["boot_id"],
        "canaryId": key["canary_id"], "fleetId": key["fleet_id"], "instanceId": key["instance_id"],
        "memberId": key["member_id"], "memberOrdinal": key["member_ordinal"], "membershipRevision": key["membership_revision"],
        "membershipRootSha256": key["membership_root_digest"], "notAfterEpochNs": key["not_after_epoch_ns"],
        "notBeforeEpochNs": key["not_before_epoch_ns"], "publicKeySpkiSha256": key["public_key_digest"],
        "role": key["role"], "teeMeasurementSha256": key["tee_measurement_digest"]}
    return db._policy_authority_domain_digest(b"catchplate.policyRuntimeRoleAuthorization/v1", profile.canonical(value))


def verify_runtime_original(*, evidence_kind, assignment_envelope_digest, member_ordinal, canary_id, fleet_id,
        membership_revision, instance_id, boot_id, envelope_json, envelope_digest, payload_json, payload_digest,
        signature_algorithm, signing_key_id, signature, signature_digest, record_binding, key, member, revocations,
        verified_at_epoch_ns):
    from catchplate import db
    contract = db._POLICY_AUTHORITY_RUNTIME_EVIDENCE_DOMAINS.get(evidence_kind)
    profile.require(contract is not None)
    required_role, domain, expected_kind = contract
    for name, value in (("member_ordinal", member_ordinal), ("membership_revision", membership_revision)):
        db._candidate_authority_int(name, value, minimum=1)
    for name, value in (("canary_id", canary_id), ("instance_id", instance_id), ("boot_id", boot_id)):
        db._candidate_authority_text(name, value, maximum=256)
    db._candidate_authority_digest("fleet_id", fleet_id)
    db._candidate_authority_digest("assignment_envelope_digest", assignment_envelope_digest)
    envelope_json, envelope_digest = db._candidate_authority_json("runtime envelope", envelope_json, envelope_digest)
    payload_json, payload_digest = db._candidate_authority_json("runtime payload", payload_json, payload_digest,
        maximum=4 * 1024 * 1024)
    db._candidate_authority_signature_fields({"signature_algorithm": signature_algorithm, "signing_key_id": signing_key_id,
        "signature": signature, "signature_digest": signature_digest})
    signature_bytes = db._candidate_authority_b64url("runtime signature", signature, expected_bytes=64)
    profile.require(profile.sha256(signature_bytes) == signature_digest)
    envelope, payload = db.loads(envelope_json, None), db.loads(payload_json, None)
    profile.require(type(envelope) is dict and set(envelope) == {"apiVersion", "kind", "canonicalProfile", "signatureDomain",
        "payload", "payloadSha256", "signatureAlgorithm", "signingKeyId", "signingKeySpkiSha256", "signature"}
        and envelope["apiVersion"] == envelope["signatureDomain"] == domain and envelope["kind"] == expected_kind
        and envelope["canonicalProfile"] == db._POLICY_AUTHORITY_CANONICAL_PROFILE and envelope["payload"] == payload
        and envelope["payloadSha256"] == payload_digest and envelope["signatureAlgorithm"] == signature_algorithm == "Ed25519"
        and envelope["signingKeyId"] == signing_key_id and envelope["signature"] == signature)
    bound = dict(record_binding)
    db._candidate_authority_json_value("runtime binding", bound)
    if evidence_kind in db._POLICY_SHADOW_DIRECT_RUNTIME_EVIDENCE_KINDS:
        profile.require(type(payload) is dict and set(payload) == db._POLICY_SHADOW_DIRECT_PAYLOAD_FIELDS[evidence_kind])
        db._policy_shadow_assert_direct_record_binding(evidence_kind=evidence_kind, payload=payload, record_binding=bound)
        issued, expires = payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"]
    else:
        profile.require(type(payload) is dict and set(payload) == {"issuedAtEpochNs", "expiresAtEpochNs", "record"}
            and payload["record"] == bound)
        issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    for name, value in (("issued", issued), ("expires", expires), ("verified", verified_at_epoch_ns)):
        db._candidate_authority_int(name, value)
    profile.require(0 <= issued < expires and verified_at_epoch_ns > 0 and type(key) is dict and type(member) is dict)
    expected = {"assignment_envelope_digest": assignment_envelope_digest, "member_ordinal": member_ordinal,
        "canary_id": canary_id, "fleet_id": fleet_id, "membership_revision": membership_revision,
        "instance_id": instance_id, "boot_id": boot_id, "role": required_role, "signing_key_id": signing_key_id}
    profile.require(all(key[name] == value for name, value in expected.items()))
    joined = ("assignment_envelope_digest", "member_ordinal", "canary_id", "fleet_id", "membership_revision",
        "membership_root_digest", "member_id", "instance_id", "boot_id", "tee_measurement_digest", "attestation_receipt_envelope_digest")
    profile.require(all(member[name] == key[name] for name in joined))
    revocation_join = joined + ("role", "public_key_digest", "authorization_digest")
    profile.require(type(revocations) is list and not any(all(row[name] == key[name] for name in revocation_join) for row in revocations),
        "runtime role key is revoked")
    public_digest, _, public_bytes = db._policy_authority_public_key(label="canary assigned role",
        public_key_base64url=key["public_key_base64url"], key_id=key["signing_key_id"], spki_digest=key["public_key_digest"])
    profile.require(envelope["signingKeySpkiSha256"] == public_digest and key["authorization_digest"] == role_authorization(key)
        and key["not_before_epoch_ns"] <= verified_at_epoch_ns < key["not_after_epoch_ns"]
        and key["not_before_epoch_ns"] <= issued < expires <= key["not_after_epoch_ns"]
        and issued <= verified_at_epoch_ns + db._POLICY_AUTHORITY_ROOT_MAX_CLOCK_SKEW_NS
        and verified_at_epoch_ns - issued <= db._POLICY_AUTHORITY_ROOT_RECEIPT_MAX_AGE_NS and verified_at_epoch_ns < expires)
    message = b"\0".join((db._POLICY_AUTHORITY_SIGNATURE_FRAME, domain.encode("ascii"),
        db._POLICY_AUTHORITY_CANONICAL_PROFILE.encode("ascii"), payload_json.encode("ascii")))
    Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature_bytes, message)
    binding_digest = db._policy_authority_domain_digest(b"catchplate.policyRuntimeRecordBinding/v1",
        domain.encode("ascii"), profile.canonical(bound))
    sequence = max((row["revocation_sequence"] for row in revocations), default=0)
    message_digest = profile.sha256(message)
    receipt = {"assignmentEnvelopeDigest": assignment_envelope_digest,
        "attestationReceiptEnvelopeDigest": key["attestation_receipt_envelope_digest"], "bootId": boot_id, "canaryId": canary_id,
        "envelopeDigest": envelope_digest, "evidenceKind": evidence_kind, "expiresAtEpochNs": expires, "fleetId": fleet_id,
        "instanceId": instance_id, "issuedAtEpochNs": issued, "memberOrdinal": member_ordinal,
        "membershipRevision": membership_revision, "membershipRootSha256": key["membership_root_digest"],
        "payloadDigest": payload_digest, "publicKeySpkiSha256": public_digest, "recordBindingDigest": binding_digest,
        "requiredRole": required_role, "roleAuthorizationDigest": key["authorization_digest"], "runtimeRevocationSequence": sequence,
        "signatureDigest": signature_digest, "signatureMessageDigest": message_digest}
    return {"verification_receipt_digest": profile.sha256(profile.canonical(receipt)), "evidence_kind": evidence_kind,
        "required_role": required_role, "assignment_envelope_digest": assignment_envelope_digest, "member_ordinal": member_ordinal,
        "canary_id": canary_id, "fleet_id": fleet_id, "membership_revision": membership_revision, "instance_id": instance_id,
        "boot_id": boot_id, "signing_key_id": signing_key_id, "public_key_digest": public_digest, "signature_domain": domain,
        "signature": signature, "signature_digest": signature_digest, "record_binding_digest": binding_digest,
        "envelope_digest": envelope_digest, "payload_digest": payload_digest, "signature_message_digest": message_digest,
        "role_authorization_digest": key["authorization_digest"], "attestation_receipt_envelope_digest": key["attestation_receipt_envelope_digest"],
        "revocation_sequence": sequence, "issued_at_epoch_ns": issued, "expires_at_epoch_ns": expires, "verified_at_epoch_ns": verified_at_epoch_ns}
