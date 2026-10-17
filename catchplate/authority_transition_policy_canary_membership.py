"""Typed assignment and load producers over the authenticated batch overlay."""
from catchplate import authority_policy_canary as profile
from catchplate import authority_policy_canary_evidence as signatures
from catchplate.authority_transition_policy_canary_state import exact, apply_verification

CANARY_COLUMNS = ("canary_id", "artifact_envelope_digest", "artifact_payload_digest", "policy_id", "candidate_policy_sequence",
    "candidate_rollback_epoch", "candidate_policy_hash", "predecessor_policy_sequence", "predecessor_rollback_epoch",
    "predecessor_policy_hash", "compiler_digest", "compiler_config_digest", "policy_schema_digest", "semantic_model_digest",
    "evaluator_abi_digest", "policy_bundle_digest", "runtime_digest", "thresholds_digest", "expected_instance_count",
    "minimum_evaluation_count", "created_by", "created_at_epoch_ns")
ASSIGNMENT_COLUMNS = ("assignment_envelope_digest", "assignment_payload_digest", "canary_id", "artifact_envelope_digest",
    "artifact_payload_digest", "candidate_policy_hash", "compiler_digest", "compiler_config_digest", "policy_schema_digest",
    "semantic_model_digest", "evaluator_abi_digest", "policy_bundle_digest", "runtime_digest", "assignment_id", "assignment_revision",
    "generation_epoch", "minimum_generation_tombstone_epoch", "fleet_id", "membership_revision", "membership_root_digest",
    "member_list_json", "member_list_digest", "attestation_set_json", "attestation_set_digest", "expected_snapshots_json",
    "expected_snapshots_digest", "response_obligations_json", "response_obligations_json_digest", "response_obligations_digest",
    "observation_window_json", "observation_window_digest", "readiness_thresholds_json", "readiness_thresholds_digest",
    "assignment_envelope_json", "assignment_payload_json", "signature_algorithm", "signing_key_id", "signature", "signature_digest",
    "evidence_kind", "record_binding_digest", "verification_receipt_digest", "issued_at_epoch_ns", "expires_at_epoch_ns")
SNAPSHOT_FIELDS = ("artifact_envelope_digest", "artifact_payload_digest", "candidate_policy_hash", "compiler_digest",
    "compiler_config_digest", "policy_schema_digest", "semantic_model_digest", "evaluator_abi_digest", "policy_bundle_digest", "runtime_digest")
MEMBER_FIELDS = ("canary_id", "fleet_id", "membership_revision", "membership_root_digest", "member_ordinal", "member_id",
    "instance_id", "boot_id", "assignment_envelope_digest", "assignment_payload_digest")


def record(value, fields):
    from catchplate import db
    item = db._candidate_authority_record("controlled canary original", value, fields)
    for name, current in item.items():
        if current is not None and (name.endswith("_digest") or name.endswith("_hash")):
            db._candidate_authority_digest(name, current)
    db._candidate_authority_signature_fields(item)
    return item


def integers(item, positive=(), nonnegative=()):
    from catchplate import db
    for name in positive:
        db._candidate_authority_int(name, item[name], minimum=1)
    for name in nonnegative:
        db._candidate_authority_int(name, item[name])


def assignment(state, value):
    from catchplate import db
    item = record(value, db._POLICY_CANARY_ASSIGNMENT_FIELDS)
    integers(item, ("candidate_policy_sequence", "candidate_rollback_epoch", "predecessor_policy_sequence", "predecessor_rollback_epoch",
        "assignment_revision", "generation_epoch", "minimum_generation_tombstone_epoch", "membership_revision",
        "expected_instance_count", "minimum_evaluation_count"), ("created_at_epoch_ns", "issued_at_epoch_ns", "expires_at_epoch_ns"))
    profile.require(item["created_at_epoch_ns"] <= item["issued_at_epoch_ns"] < item["expires_at_epoch_ns"])
    for name, maximum in (("canary_id", 256), ("policy_id", 256), ("created_by", 1024)):
        db._candidate_authority_text(name, item[name], maximum=maximum)
    profile.digest(item["fleet_id"]); profile.digest(item["assignment_id"])
    members = db._validate_policy_assignment_contract(item)
    verified = state.static("canary_assignment", item, "assignment", db._candidate_authority_signed_record(item, current_prefix="assignment"))
    apply_verification(item, verified)
    artifact = state.one("policy_candidate_artifacts", artifact_envelope_digest=item["artifact_envelope_digest"])
    mapping = {"candidate_policy_sequence": "policy_sequence", "candidate_rollback_epoch": "rollback_epoch", "candidate_policy_hash": "policy_hash"}
    for name in ("artifact_payload_digest", "policy_id", "candidate_policy_sequence", "candidate_rollback_epoch", "candidate_policy_hash",
            "predecessor_policy_sequence", "predecessor_rollback_epoch", "predecessor_policy_hash", "compiler_digest",
            "compiler_config_digest", "policy_schema_digest", "semantic_model_digest", "evaluator_abi_digest", "policy_bundle_digest", "runtime_digest"):
        profile.require(item[name] == artifact[mapping.get(name, name)])
    state.put("policy_canaries", {name: item[name] for name in CANARY_COLUMNS})
    transition = state.transition(event_type="policy.canary_assignment.staged", entity_kind="canary_assignment",
        entity_id=item["canary_id"], entity_revision=1, state_digest=item["assignment_payload_digest"], previous_state_digest=None,
        actor_id=item["created_by"], evidence={"assignmentEnvelopeDigest": item["assignment_envelope_digest"],
            "assignmentPayloadDigest": item["assignment_payload_digest"], "artifactEnvelopeDigest": item["artifact_envelope_digest"],
            "candidatePolicyHash": item["candidate_policy_hash"]}, created_at_epoch_ns=item["issued_at_epoch_ns"])
    result = {**{name: item[name] for name in ASSIGNMENT_COLUMNS}, "created_transition_digest": transition}
    state.put("policy_canary_assignments", result)
    for member in members:
        raw = member["attestation"]
        attestation = {"attestation_receipt_envelope_json": raw["envelopeJson"], "attestation_receipt_envelope_digest": raw["envelopeDigest"],
            "attestation_receipt_payload_json": raw["payloadJson"], "attestation_receipt_payload_digest": raw["payloadDigest"],
            "signature_algorithm": raw["signatureAlgorithm"], "signing_key_id": raw["signingKeyId"],
            "signature": raw["signature"], "signature_digest": raw["signatureDigest"]}
        checked = state.static("runtime_attestation", attestation, "attestation_receipt", member["attestation_record"])
        initial_role = member["roles"][0]
        profile.require(initial_role["role"] == "attestation" and initial_role["not_before_epoch_ns"] <= checked["issued_at_epoch_ns"]
            and checked["expires_at_epoch_ns"] <= initial_role["not_after_epoch_ns"])
        member_row = {name: item[name] for name in ("assignment_envelope_digest", "assignment_payload_digest", "canary_id", "fleet_id",
            "membership_revision", "membership_root_digest")}
        member_row.update(member_ordinal=member["ordinal"], member_leaf_digest=member["member_leaf_digest"],
            member_canonical_json=member["member_json"], member_id=member["member_id"], instance_id=member["instance_id"], boot_id=member["boot_id"],
            workload_spiffe_id=member["spiffe_id"], tee_platform=member["tee_platform"], tee_measurement_digest=member["tee_measurement_digest"],
            attestation_receipt_envelope_digest=raw["envelopeDigest"], attestation_receipt_payload_digest=raw["payloadDigest"],
            assigned_at_epoch_ns=item["created_at_epoch_ns"])
        attestation.update({name: member_row[name] for name in MEMBER_FIELDS})
        attestation.update(workload_spiffe_id=member["spiffe_id"], tee_platform=member["tee_platform"], tee_evidence_digest=member["tee_evidence_digest"],
            tee_measurement_digest=member["tee_measurement_digest"], attestation_key_id=initial_role["key_id"],
            attestation_key_spki_digest=initial_role["public_key_digest"])
        apply_verification(attestation, checked, interval=True)
        state.put("policy_runtime_attestations", attestation)
        state.put("policy_canary_assignment_members", member_row)
        for role in member["roles"]:
            profile.require(role["not_before_epoch_ns"] <= item["issued_at_epoch_ns"]
                and item["expires_at_epoch_ns"] <= role["not_after_epoch_ns"])
            role_row = {name: member_row[name] for name in MEMBER_FIELDS if name != "assignment_payload_digest"}
            role_row.update(role=role["role"], signing_key_id=role["key_id"], public_key_base64url=role["public_key_base64url"],
                public_key_digest=role["public_key_digest"], attestation_receipt_envelope_digest=raw["envelopeDigest"],
                tee_measurement_digest=member["tee_measurement_digest"], not_before_epoch_ns=role["not_before_epoch_ns"],
                not_after_epoch_ns=role["not_after_epoch_ns"])
            role_row["authorization_digest"] = signatures.role_authorization(role_row)
            state.put("policy_runtime_role_keys", role_row)
        instance = {**{name: member_row[name] for name in MEMBER_FIELDS}, **{name: item[name] for name in SNAPSHOT_FIELDS}}
        instance.update(workload_spiffe_id=member["spiffe_id"], tee_platform=member["tee_platform"], attestation_evidence_digest=member["tee_evidence_digest"],
            attestation_verifier_receipt_digest=raw["envelopeDigest"], boot_public_key_digest=initial_role["public_key_digest"],
            boot_signing_key_id=initial_role["key_id"], assigned_at_epoch_ns=item["created_at_epoch_ns"])
        state.put("policy_canary_instances", instance)
    return result


def load_receipt(state, value):
    from catchplate import db
    item = record(value, db._POLICY_CANARY_LOAD_RECEIPT_FIELDS)
    actor = db._candidate_authority_text("load actor", item.pop("actor_id"), maximum=1024)
    integers(item, ("membership_revision", "member_ordinal"), ("assigned_at_epoch_ns", "loaded_at_epoch_ns"))
    profile.require(item["signing_key_id"] == item["boot_signing_key_id"] and item["assigned_at_epoch_ns"] <= item["loaded_at_epoch_ns"])
    for name in ("canary_id", "member_id", "instance_id", "boot_id"):
        db._candidate_authority_text(name, item[name], maximum=256)
    db._candidate_authority_text("workload_spiffe_id", item["workload_spiffe_id"], maximum=2048)
    db._candidate_authority_text("tee_platform", item["tee_platform"], maximum=128)
    assignment_row = state.one("policy_canary_assignments", canary_id=item["canary_id"], assignment_envelope_digest=item["assignment_envelope_digest"])
    exact(item, assignment_row, SNAPSHOT_FIELDS + ("assignment_payload_digest", "fleet_id", "membership_revision", "membership_root_digest"))
    instance = state.one("policy_canary_instances", **{name: item[name] for name in ("canary_id", "instance_id", "boot_id")})
    exact(item, instance, tuple(instance))
    member = state.one("policy_canary_assignment_members", assignment_envelope_digest=item["assignment_envelope_digest"], member_ordinal=item["member_ordinal"])
    profile.require(member["attestation_receipt_envelope_digest"] == item["attestation_verifier_receipt_digest"])
    verified = state.runtime("load_receipt", item, "load_receipt",
        db._candidate_authority_signed_record({**item, "actor_id": actor}, current_prefix="load_receipt"))
    profile.require(verified["public_key_digest"] == item["boot_public_key_digest"])
    apply_verification(item, verified)
    transition = state.transition(event_type="policy.canary_load_receipt.staged", entity_kind="load_receipt",
        entity_id="/".join(item[name] for name in ("canary_id", "instance_id", "boot_id")), entity_revision=1,
        state_digest=item["load_receipt_payload_digest"], previous_state_digest=item["assignment_payload_digest"], actor_id=actor,
        evidence={"loadReceiptEnvelopeDigest": item["load_receipt_envelope_digest"], "loadReceiptPayloadDigest": item["load_receipt_payload_digest"],
            "assignmentPayloadDigest": item["assignment_payload_digest"], "attestationVerifierReceiptDigest": item["attestation_verifier_receipt_digest"]},
        created_at_epoch_ns=item["loaded_at_epoch_ns"])
    # These three inputs participate in the original signature/instance join;
    # the existing immutable load relation deliberately does not duplicate them.
    result = {name: current for name, current in item.items() if name not in {"workload_spiffe_id", "tee_platform", "assigned_at_epoch_ns"}}
    result["created_transition_digest"] = transition
    state.put("policy_canary_load_receipts", result)
    return result
