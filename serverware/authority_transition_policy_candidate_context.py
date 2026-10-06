"""Fixed candidate generation reads and exact protected predecessor joins."""
from serverware import authority_policy_candidate as profile
from serverware import authority_policy_candidate_inventory as inventory
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared


def exact(operation, name, table, key, *, absence=False):
    return shared._query(operation=operation, name=name, table=table, key=key, require_absence=absence)


def population(context, table):
    # KernelContext exposes authenticated selections, not their row bodies.
    return tuple(shared._row(selected, "candidate population " + table)
        for selected in context.present_rows(table))


def populations(operation):
    from serverware import authority_primary_contract as primary
    return tuple(core.BoundedQuery(query_id=core.query_program_id(operation, "complete_population", table),
        table=table, predicates=(), order_by=tuple(core.QueryOrder(field) for field in primary.PRIMARY_KEY_COLUMNS[table]),
        maximum_rows=inventory.MAX_ROWS + 1, proof_primitive="bounded-limit-plus-one", work_units=inventory.MAX_ROWS + 1, page_size=inventory.MAX_ROWS)
        for table in inventory.tables_for(operation))


def queries(operation, bound, request):
    from serverware import db
    original = db._policy_shadow_runtime_attestation_handoff_components(request["runtimeAttestation"])
    return (
        exact(operation, "candidate_artifact", "policy_candidate_artifacts", {"artifact_envelope_digest": bound["artifactEnvelopeDigest"]}),
        exact(operation, "candidate_assignment", "policy_canary_assignments", {"assignment_envelope_digest": bound["assignmentEnvelopeDigest"]}),
        exact(operation, "assigned_member", "policy_canary_assignment_members", {
            "assignment_envelope_digest": bound["assignmentEnvelopeDigest"], "member_ordinal": bound["memberOrdinal"]}),
        exact(operation, "load_receipt", "policy_canary_load_receipts", {"load_receipt_envelope_digest": bound["loadReceiptEnvelopeDigest"]}),
        exact(operation, "native_handoff", "policy_shadow_runtime_attestation_handoffs", {
            "runtime_attestation_handoff_digest": bound["runtimeAttestationHandoffDigest"]}),
        exact(operation, "native_attestation", "policy_runtime_attestations", {
            "attestation_receipt_envelope_digest": original["handoff"]["receiptSha256"]}),
        exact(operation, "shadow_key", "policy_runtime_role_keys", {"assignment_envelope_digest": bound["assignmentEnvelopeDigest"],
            "member_ordinal": bound["memberOrdinal"], "role": "shadow", "public_key_digest": bound["shadowKeySha256"]}),
        exact(operation, "canary_head", "policy_canary_heads", {"canary_id": bound["canaryId"]}),
        exact(operation, "current_policy", "policy_high_water", {"scope": "active"}),
    )


def original_context(context, bound, request):
    from serverware import db

    def row(table, key):
        return shared._row(context.exact(table, key), "actual candidate " + table)

    parsed = db._policy_shadow_runtime_attestation_handoff_components(request["runtimeAttestation"])
    artifact = row("policy_candidate_artifacts", {"artifact_envelope_digest": bound["artifactEnvelopeDigest"]})
    assignment = row("policy_canary_assignments", {"assignment_envelope_digest": bound["assignmentEnvelopeDigest"]})
    member = row("policy_canary_assignment_members", {"assignment_envelope_digest": bound["assignmentEnvelopeDigest"],
        "member_ordinal": bound["memberOrdinal"]})
    load = row("policy_canary_load_receipts", {"load_receipt_envelope_digest": bound["loadReceiptEnvelopeDigest"]})
    handoff = row("policy_shadow_runtime_attestation_handoffs", {"runtime_attestation_handoff_digest": bound["runtimeAttestationHandoffDigest"]})
    attestation = row("policy_runtime_attestations", {"attestation_receipt_envelope_digest": parsed["handoff"]["receiptSha256"]})
    key = row("policy_runtime_role_keys", {"assignment_envelope_digest": bound["assignmentEnvelopeDigest"],
        "member_ordinal": bound["memberOrdinal"], "role": "shadow", "public_key_digest": bound["shadowKeySha256"]})
    head = row("policy_canary_heads", {"canary_id": bound["canaryId"]})
    active = row("policy_high_water", {"scope": "active"})
    now = shared._database_epoch_ns(context.database_now)
    profile.require(head["status"] not in {"indeterminate", "failed", "cancelled", "expired", "superseded", "active", "completed"},
        "candidate head is no longer an unactivated generation")
    profile.require(artifact["candidate_id"] == bound["candidateId"] and assignment["canary_id"] == bound["canaryId"]
        and assignment["artifact_envelope_digest"] == artifact["artifact_envelope_digest"]
        and assignment["artifact_payload_digest"] == artifact["artifact_payload_digest"]
        and assignment["candidate_policy_hash"] == artifact["policy_hash"]
        and assignment["policy_bundle_digest"] == artifact["policy_bundle_digest"]
        and request["assignment"] == db.loads(assignment["assignment_envelope_json"], None)
        and request["loadReceipt"] == db.loads(load["load_receipt_envelope_json"], None)
        and request["runtimeAttestation"] == db.loads(handoff["runtime_attestation_handoff_json"], None)
        and parsed["handoff_digest"] == bound["runtimeAttestationHandoffDigest"])
    for item in (member, load, handoff, key):
        profile.require(item["canary_id"] == bound["canaryId"] and item["instance_id"] == bound["instanceId"]
            and item["boot_id"] == bound["bootId"] and item["assignment_envelope_digest"] == bound["assignmentEnvelopeDigest"])
    for item in (member, load, key):
        profile.require(item["member_ordinal"] == bound["memberOrdinal"] and item["fleet_id"] == assignment["fleet_id"]
            and item["membership_revision"] == assignment["membership_revision"]
            and item["membership_root_digest"] == assignment["membership_root_digest"])
    profile.require(load["load_receipt_envelope_digest"] == handoff["load_receipt_envelope_digest"]
        == bound["loadReceiptEnvelopeDigest"] and load["load_receipt_payload_digest"] == handoff["load_receipt_payload_digest"]
        and member["attestation_receipt_envelope_digest"] == key["attestation_receipt_envelope_digest"]
        == attestation["attestation_receipt_envelope_digest"] == handoff["receipt_envelope_digest"]
        and key["public_key_digest"] == key["signing_key_id"] == handoff["shadow_signing_key_id"] == bound["shadowKeySha256"]
        and key["authorization_digest"] == handoff["shadow_role_key_authorization_digest"]
        and parsed["receipt"]["envelope_json"] == attestation["attestation_receipt_envelope_json"]
        and parsed["receipt"]["payload_json"] == attestation["attestation_receipt_payload_json"]
        and key["not_before_epoch_ns"] <= now < key["not_after_epoch_ns"]
        and handoff["issued_at_epoch_ns"] <= now < handoff["expires_at_epoch_ns"]
        and assignment["issued_at_epoch_ns"] <= now < assignment["expires_at_epoch_ns"]
        and attestation["tee_platform"] == "aws-nitro-enclave" and member["tee_platform"] == "aws-nitro-enclave")
    for revoked in population(context, "policy_runtime_role_key_revocations"):
        profile.require(not (revoked["assignment_envelope_digest"] == bound["assignmentEnvelopeDigest"]
            and revoked["member_ordinal"] == bound["memberOrdinal"] and revoked["role"] == "shadow"
            and revoked["public_key_digest"] == bound["shadowKeySha256"]), "assigned shadow key is revoked")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    public_key = Ed25519PublicKey.from_public_bytes(db._candidate_authority_b64url(
        "actual attested shadow key", key["public_key_base64url"], expected_bytes=32))
    profile.require(profile.sha256(public_key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)) == bound["shadowKeySha256"])
    for revoked in population(context, "policy_authority_trusted_key_revocations"):
        profile.require(revoked["signing_key_id"] not in {artifact["signing_key_id"], assignment["signing_key_id"],
            parsed["role_authorization"]["signing_key_id"], attestation["signing_key_id"], bound["shadowKeySha256"]},
            "candidate original signing authority is revoked")
    candidate_digest = profile.sha256(profile.canonical(request["candidatePolicyBundle"]))
    active_digest = profile.sha256(profile.canonical(request["activePolicyBundle"]))
    profile.require(candidate_digest == artifact["policy_bundle_digest"])
    # policy_hash strips only the existing signature field. It performs no key
    # lookup, schema I/O or signing; original authority remains the proved rows.
    from serverware.policy_bundle import policy_hash
    profile.require(policy_hash(request["candidatePolicyBundle"]) == artifact["policy_hash"]
        and policy_hash(request["activePolicyBundle"]) == active["policy_hash"]
        and active["policy_id"] == artifact["policy_id"]
        and active["policy_hash"] == assignment["predecessor_policy_hash"]
        and active["sequence"] == assignment["predecessor_policy_sequence"]
        and active["rollback_epoch"] == assignment["predecessor_rollback_epoch"])
    from serverware import authority_transition_policy_candidate_trust as trust
    trust.stored_static(context, kind="runtime_attestation", row=attestation, prefix="attestation_receipt")
    role = parsed["role_record"]
    signed_role = parsed["role_authorization"]
    role_verified = trust.historical(context, receipt_digest=handoff["role_authorization_verification_receipt_digest"],
        evidence_kind="shadow_role_authorization", record_binding=role, **{field: signed_role[field] for field in
            ("envelope_json", "envelope_digest", "payload_json", "payload_digest", "signature_algorithm",
                "signing_key_id", "signature", "signature_digest")})
    load_payload = db.loads(load["load_receipt_payload_json"], None)
    profile.require(type(load_payload) is dict and type(load_payload.get("runtimeIdentity")) is dict)
    runtime_identity = profile.sha256(profile.canonical(load_payload["runtimeIdentity"]))
    expected_role = {"candidateId": bound["candidateId"], "canaryId": bound["canaryId"],
        "assignmentSha256": bound["assignmentEnvelopeDigest"], "assignmentPayloadSha256": assignment["assignment_payload_digest"],
        "assignmentRevision": assignment["assignment_revision"], "loadReceiptSha256": bound["loadReceiptEnvelopeDigest"],
        "loadReceiptPayloadSha256": load["load_receipt_payload_digest"], "fleetId": assignment["fleet_id"],
        "fleetMembershipRevision": assignment["membership_revision"], "membershipRootSha256": assignment["membership_root_digest"],
        "memberOrdinal": bound["memberOrdinal"], "memberId": member["member_id"], "instanceId": bound["instanceId"],
        "bootIdSha256": bound["bootId"], "runtimeIdentitySha256": runtime_identity,
        "runtimeExecutableSha256": assignment["runtime_digest"], "shadowSigningKeyId": key["signing_key_id"],
        "shadowSigningKeySpkiSha256": key["public_key_digest"], "teeMeasurementSha256": attestation["tee_measurement_digest"]}
    profile.require(all(role[field] == value for field, value in expected_role.items()))
    native = parsed["handoff"]
    chain = db._policy_shadow_generation_rust_domain_digest(b"serverware.policyShadowRuntimeAttestationEvidenceChain/v1", [
        "serverware.policyShadowRuntimeAttestationHandoff/v2", native["receiptId"], native["receiptRevision"],
        native["receiptSha256"], native["receiptPayloadSha256"], native["roleAuthorizationId"],
        native["roleAuthorizationRevision"], native["roleAuthorizationSha256"], native["roleAuthorizationPayloadSha256"],
        parsed["evidence"], assignment["assignment_payload_digest"], load["load_receipt_payload_digest"],
        runtime_identity, role["attestationPolicySha256"]])
    profile.require(native["chainSha256"] == chain == handoff["attestation_chain_digest"]
        and parsed["evidence"]["evidenceSha256"] == attestation["tee_evidence_digest"]
        and parsed["evidence"]["evidenceType"] == attestation["tee_platform"]
        and parsed["receipt_issued_at_epoch_ns"] <= now < parsed["receipt_expires_at_epoch_ns"]
        and parsed["role_issued_at_epoch_ns"] <= now < parsed["role_expires_at_epoch_ns"])
    exact_handoff = {"candidate_id": bound["candidateId"], "assignment_payload_digest": assignment["assignment_payload_digest"],
        "assignment_revision": assignment["assignment_revision"], "receipt_id": native["receiptId"],
        "receipt_revision": native["receiptRevision"], "receipt_payload_digest": native["receiptPayloadSha256"],
        "role_authorization_id": native["roleAuthorizationId"], "role_authorization_revision": native["roleAuthorizationRevision"],
        "role_authorization_envelope_digest": native["roleAuthorizationSha256"],
        "role_authorization_payload_digest": native["roleAuthorizationPayloadSha256"],
        "role_authorization_evidence_kind": "shadow_role_authorization",
        "role_authorization_record_binding_digest": role_verified["record_binding_digest"],
        "attestation_evidence_id": parsed["evidence"]["evidenceId"], "attestation_evidence_revision": parsed["evidence"]["evidenceRevision"],
        "attestation_evidence_type": parsed["evidence"]["evidenceType"], "attestation_evidence_digest": parsed["evidence"]["evidenceSha256"],
        "attestation_evidence_json": parsed["evidence_json"], "runtime_identity_digest": runtime_identity,
        "runtime_executable_digest": role["runtimeExecutableSha256"], "runtime_release_digest": role["runtimeReleaseSha256"],
        "runtime_config_digest": role["runtimeConfigSha256"], "runtime_policy_digest": role["runtimePolicySha256"],
        "attestation_policy_digest": role["attestationPolicySha256"], "attestation_trust_checkpoint_digest": role["attestationTrustCheckpointSha256"],
        "attestation_revocation_generation": role["revocationGeneration"], "attestation_revocation_root_digest": role["revocationRootSha256"],
        "shadow_signing_key_spki_digest": role["shadowSigningKeySpkiSha256"], "tee_measurement_digest": attestation["tee_measurement_digest"],
        "issued_at_epoch_ns": parsed["role_issued_at_epoch_ns"],
        "expires_at_epoch_ns": min(parsed["role_expires_at_epoch_ns"], parsed["receipt_expires_at_epoch_ns"])}
    exact_handoff.update({"role_authorization_" + field: signed_role[field] for field in
        ("envelope_json", "payload_json", "signature_algorithm", "signing_key_id", "signature", "signature_digest")})
    profile.require(all(handoff[field] == value for field, value in exact_handoff.items()), "retained native handoff projection changed")
    return {"artifact": artifact, "assignment": assignment, "member": member, "load": load, "handoff": handoff,
        "attestation": attestation, "key": key, "head": head, "active": active, "parsed": parsed,
        "candidate_bundle_digest": candidate_digest, "active_bundle_digest": active_digest}
