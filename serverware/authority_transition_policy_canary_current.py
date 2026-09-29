"""Readiness's exact committed-policy and current-revocation joins.

All populations are authenticated to the same before-root. A high-water tuple
alone is not a finalized publication, and a caller snapshot is not a head.
"""
from serverware import authority_policy_canary as profile


def committed_policy(state):
    from serverware import db
    high = state.one("policy_high_water", optional=True, scope="active")
    if high is None:
        return None
    publication = state.one("policy_publications", optional=True, status="committed",
        **{name: high[name] for name in ("scope", "policy_id", "sequence", "rollback_epoch", "policy_hash")})
    if publication is None:
        return None
    matches = []
    for preparation in state.matching("policy_activation_preparations", candidate_policy_hash=high["policy_hash"],
            candidate_policy_sequence=high["sequence"], candidate_rollback_epoch=high["rollback_epoch"]):
        attempt_id = preparation["activation_attempt_id"]
        attempts = state.matching("policy_activation_attempts", activation_attempt_id=attempt_id)
        heads = state.matching("policy_activation_heads", activation_attempt_id=attempt_id, status="committed", unresolved_indeterminate=0)
        if len(attempts) != 1 or len(heads) != 1 or not state.matching("policy_canary_heads", canary_id=attempts[0]["canary_id"], status="active"):
            continue
        finalizations = state.matching("policy_activation_finalizations", preparation_digest=preparation["preparation_digest"], activation_attempt_id=attempt_id)
        consumptions = state.matching("policy_activation_approval_consumptions", activation_attempt_id=attempt_id,
            approval_id=preparation["approval_id"], consumption_digest=preparation["approval_consumption_digest"])
        prepared = state.matching("policy_activation_prepared_transitions", preparation_digest=preparation["preparation_digest"])
        if len(finalizations) != 1 or len(consumptions) != 1 or len(prepared) != preparation["transition_count"]:
            continue
        finalization = finalizations[0]
        receipts = state.matching("policy_activation_publication_receipts", activation_attempt_id=attempt_id,
            committed_policy_hash=high["policy_hash"], committed_policy_sequence=high["sequence"], committed_rollback_epoch=high["rollback_epoch"],
            publication_status="committed", publication_receipt_payload_digest=finalization["publication_receipt_payload_digest"])
        if len(receipts) != 1 or any(not state.matching("policy_authority_audit_inclusion_receipts", transition_digest=row["transition_digest"],
                outbox_id=row["outbox_id"], outbox_event_digest=row["outbox_event_digest"]) for row in prepared):
            continue
        matches.append({**high, "preparation_digest": preparation["preparation_digest"], "activation_attempt_id": attempt_id,
            "finalization_digest": finalization["finalization_digest"], "inclusion_identity_set_digest": finalization["inclusion_identity_set_digest"],
            "publication_receipt_payload_digest": receipts[0]["publication_receipt_payload_digest"], "consumption_digest": consumptions[0]["consumption_digest"]})
    profile.require(len(matches) <= 1, "committed canary policy has ambiguous finalization originals")
    if matches:
        return matches[0]
    if publication["previous_policy_hash"] is not None:
        return None
    for finalization in state.matching("policy_authority_genesis_finalizations", policy_id=high["policy_id"],
            policy_sequence=high["sequence"], rollback_epoch=high["rollback_epoch"], policy_hash=high["policy_hash"]):
        preparations = state.matching("policy_authority_genesis_preparations", genesis_preparation_digest=finalization["genesis_preparation_digest"],
            high_water_digest=finalization["high_water_digest"])
        inclusions = state.matching("policy_authority_audit_inclusion_receipts",
            inclusion_receipt_envelope_digest=finalization["inclusion_receipt_envelope_digest"], transition_digest=finalization["genesis_transition_digest"],
            audit_store_identity_digest=db._POLICY_AUTHORITY_AUDIT_STORE_IDENTITY_DIGEST,
            audit_ledger_namespace=db._POLICY_AUTHORITY_AUDIT_LEDGER_NAMESPACE,
            audit_signer_public_key_digest=db._POLICY_AUTHORITY_AUDIT_SIGNER_SPKI_DIGEST, signing_key_id=db._POLICY_AUTHORITY_AUDIT_SIGNER_SPKI_DIGEST)
        if len(preparations) != 1 or len(inclusions) != 1:
            continue
        preparation = preparations[0]
        material = {"genesisPreparationDigest": preparation["genesis_preparation_digest"], "highWaterDigest": preparation["high_water_digest"],
            "inclusionReceiptEnvelopeDigest": finalization["inclusion_receipt_envelope_digest"], "finalizedAtEpochNs": finalization["finalized_at_epoch_ns"]}
        if db._policy_candidate_high_water_digest(high) != preparation["high_water_digest"] or db._policy_authority_domain_digest(
                b"serverware.policyAuthorityGenesisFinalization/v1", profile.canonical(material)) != finalization["finalization_digest"]:
            continue
        matches.append({**high, "preparation_digest": preparation["genesis_preparation_digest"], "activation_attempt_id": None,
            "finalization_digest": finalization["finalization_digest"], "inclusion_identity_set_digest": inclusions[0]["inclusion_root_digest"],
            "publication_receipt_payload_digest": preparation["genesis_payload_digest"], "consumption_digest": None})
    profile.require(len(matches) <= 1, "committed canary genesis has ambiguous finalization originals")
    return matches[0] if matches else None


def trust_checkpoint(state, as_of_epoch_ns):
    from serverware import db
    db._candidate_authority_int("readiness trust as-of", as_of_epoch_ns)
    leaves = []
    sources = (
        ("authority-key", "policy_authority_trusted_key_revocations", ("revocation_sequence", "evidence_kind", "signing_key_id"),
            ("evidence_kind", "signing_key_id", "key_revision", "public_key_digest", "revocation_sequence", "revocation_digest", "revoked_at_epoch_ns")),
        ("runtime-role-key", "policy_runtime_role_key_revocations", ("revocation_sequence", "assignment_envelope_digest", "member_ordinal", "role", "public_key_digest"),
            ("assignment_envelope_digest", "member_ordinal", "canary_id", "fleet_id", "membership_revision", "membership_root_digest", "member_id",
                "instance_id", "boot_id", "role", "public_key_digest", "attestation_receipt_envelope_digest", "tee_measurement_digest", "authorization_digest",
                "revocation_sequence", "revocation_envelope_digest", "revoked_at_epoch_ns")),
        ("rollback-authority", "policy_activation_rollback_authority_revocations", ("revoked_at_epoch_ns", "revocation_envelope_digest"),
            ("rollback_authorization_envelope_digest", "rollback_authorization_payload_digest", "revocation_envelope_digest", "revocation_payload_digest",
                "canary_id", "candidate_policy_hash", "candidate_policy_sequence", "candidate_rollback_epoch", "revoked_at_epoch_ns")),
    )
    for source, table, order, columns in sources:
        for row in sorted(state.rows(table), key=lambda value: tuple(value[name] for name in order)):
            revoked = db._candidate_authority_int("revoked_at_epoch_ns", row["revoked_at_epoch_ns"])
            profile.require(revoked <= as_of_epoch_ns and len(leaves) < db._POLICY_AUTHORITY_READ_MAX_ROWS)
            material = {"source": source, "record": {name: row[name] for name in columns}}
            leaves.append((len(leaves) + 1, profile.sha256(profile.canonical(material))))
    root = db._policy_shadow_merkle_root(leaves)
    return {"checkpointId": db._policy_authority_domain_digest(b"serverware.policyTrustCheckpoint/v1", as_of_epoch_ns.to_bytes(8, "big"),
        len(leaves).to_bytes(8, "big"), db._candidate_authority_digest_bytes("trust revocation root", root)),
        "asOfUnixNanos": as_of_epoch_ns, "revocationGeneration": len(leaves), "revocationRootSha256": root}
