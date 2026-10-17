"""Exact native generation publication, claim settlement and audit in one CAS.

The HTTP owner supplies public key prestates only to address the deterministic
receipt queries. Every byte is compared with authenticated current rows before
any mutation; no supplied verifier result is admitted.
"""
from dataclasses import dataclass
from datetime import timezone

from catchplate import authority_policy_candidate as profile
from catchplate import authority_policy_candidate_evidence as signatures
from catchplate import authority_transition_policy_candidate_context as originals
from catchplate import authority_transition_policy_candidate_trust as trust
from catchplate import authority_transition_core as core
from catchplate import authority_transition_policy as policies
from catchplate import authority_transition_quota as shared


def prepare(values):
    from catchplate import db
    held = values["request"]
    claim = profile.scalar.document(held["claimOriginal"].encode("ascii"), 2 * profile.MAX_ORIGINAL_BYTES)
    profile.require(profile.row_original(claim).decode("ascii") == held["claimOriginal"])
    request = profile.management_original(claim["management_request_json"])
    bound = profile.scalar.document(claim["context_json"].encode("ascii"), 8192)
    item = db._candidate_authority_record("controlled generation publication", held["record"], db._POLICY_SHADOW_GENERATION_PUBLICATION_FIELDS)
    profile.require(item.pop("actor_id") == claim["actor_id"] == values["actor_id"]
        and item.pop("management_request_json") == claim["management_request_json"]
        and claim["configuration_digest"] == values["control_plane_configuration_digest"])
    for field, value in tuple(item.items()):
        if field.endswith("_digest") or field.endswith("_hash"):
            profile.digest(value)
    for field, minimum in (("assignment_revision", 1), ("generation_epoch", 1), ("minimum_generation_tombstone_epoch", 1),
            ("membership_revision", 1), ("member_ordinal", 1), ("publication_revision", 1), ("custody_sequence", 0),
            ("ingress_sequence", 0), ("active_policy_sequence", 1), ("active_rollback_epoch", 1),
            ("candidate_policy_sequence", 1), ("candidate_rollback_epoch", 1)):
        profile.require(type(item[field]) is int and minimum <= item[field] <= 9_223_372_036_854_775_807)
    profile.require(item["publication_revision"] == 1 and item["custody_sequence"] == item["ingress_sequence"] == 0
        and item["attestation_mode"] == "aws-nitro-enclave" and item["hardware_attested"] is True)
    for field in ("candidate_id", "canary_id", "member_id", "instance_id", "boot_id"):
        profile.text(item[field], 256)
    profile.require(item["request_id"] == request["requestId"] and item["replay_id"] == request["replayId"]
        and item["management_handoff_id"] == request["managementHandoffId"] and item["request_payload_digest"] == claim["payload_digest"])
    for prefix in ("generation_publication",):
        for part in ("envelope", "payload"):
            db._candidate_authority_json(prefix + part, item[prefix + "_" + part + "_json"],
                item[prefix + "_" + part + "_digest"], maximum=profile.MAX_ORIGINAL_BYTES)
    db._candidate_authority_signature_fields(item)
    projection = db._policy_shadow_generation_evidence(item)
    profile.require(request["runtimeAttestation"] == projection["startup_attestation"])
    item["management_actor_id"] = values["actor_id"]
    return claim, request, bound, item, projection


def evidence_inputs(item, projection):
    from catchplate import db
    return ({"evidence_kind": "generation_runtime_attestation_verification",
        "envelope_json": item["runtime_attestation_verification_envelope_json"],
        "envelope_digest": projection["inner"]["envelope_digest"],
        "payload_json": item["runtime_attestation_verification_payload_json"],
        "payload_digest": projection["inner"]["payload_digest"],
        "signature_algorithm": item["runtime_attestation_verifier_signature_algorithm"],
        "signing_key_id": item["runtime_attestation_verifier_signing_key_id"],
        "signature": item["runtime_attestation_verifier_signature"],
        "signature_digest": item["runtime_attestation_verifier_signature_digest"], "record_binding": projection["inner_payload"]},
        {"evidence_kind": "generation_publication", "envelope_json": item["generation_publication_envelope_json"],
        "envelope_digest": item["generation_publication_envelope_digest"], "payload_json": item["generation_publication_payload_json"],
        "payload_digest": item["generation_publication_payload_digest"], "signature_algorithm": item["signature_algorithm"],
        "signing_key_id": item["signing_key_id"], "signature": item["signature"], "signature_digest": item["signature_digest"],
        "record_binding": db._policy_shadow_generation_signed_record(item)})


def audit_stage(values, item, projection, database_now):
    return policies._audit_stage(event_type="policy.shadow_generation.published", entity_kind="shadow_generation_publication",
        entity_id=item["generation_id_digest"], entity_revision=1, state_digest=item["generation_publication_payload_digest"],
        previous_state_digest=item["load_receipt_payload_digest"], actor_id=values["actor_id"],
        evidence={"attestationChainDigest": item["attestation_chain_digest"],
            "generationPublicationEnvelopeDigest": item["generation_publication_envelope_digest"],
            "managementRequestDigest": item["request_payload_digest"], "requestId": item["request_id"]},
        created_at_epoch_ns=projection["evidence"]["issuedAtUnixNanos"],
        created_at=database_now.astimezone(timezone.utc).isoformat())


@dataclass(frozen=True, slots=True)
class GenerationPublicationKernel:
    operation: str = profile.OP_PUBLISH
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "catchplate_policy_authority_policy_candidate_generation_publish"

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        del request_digest
        values = profile.arguments(self.operation, arguments, typed=True)
        claim, request, bound, item, projection = prepare(values)
        queries = list(originals.queries(self.operation, bound, request)) + list(originals.populations(self.operation))
        queries.append(originals.exact(self.operation, "claim", profile.TABLE, {"request_id": request["requestId"]}))
        queries.append(shared._role_query(self.operation, "publisher", values["actor_id"]))
        for evidence in evidence_inputs(item, projection):
            kind = evidence["evidence_kind"]
            given = values["request"]["verificationInputs"][kind]
            expected = signatures.verify_static_original(**evidence, key=given["key"], key_head=given["head"], revocation=None,
                revocation_sequence=given["revocationSequence"], verified_at_epoch_ns=shared._database_epoch_ns(database_now))
            queries.extend((originals.exact(self.operation, kind + "_head", "policy_authority_trusted_key_heads", {"evidence_kind": kind}),
                originals.exact(self.operation, kind + "_verification", "policy_authority_evidence_verifications", {
                    "verification_receipt_digest": expected["verification_receipt_digest"]})))
        stage = audit_stage(values, item, projection, database_now)
        queries.extend((originals.exact(self.operation, "publication", "policy_shadow_generation_publications", {
                "generation_publication_envelope_digest": item["generation_publication_envelope_digest"]}, absence=True),
            originals.exact(self.operation, "transition", "policy_authority_transition_audits", {
                "transition_digest": stage["transition"]["transition_digest"]}, absence=True),
            originals.exact(self.operation, "audit", "metadata_audit_outbox", {"id": stage["outbox"]["id"]}, absence=True)))
        return tuple(queries)

    def transition(self, context):
        from catchplate import db
        values = profile.arguments(self.operation, context.arguments, typed=True)
        claim, request, bound, item, projection = prepare(values)
        selected_claim = context.exact(profile.TABLE, {"request_id": request["requestId"]})
        profile.require(profile.row_original(shared._row(selected_claim, "actual candidate claim")) == profile.row_original(claim)
            and claim["publication_envelope_digest"] is None)
        now = shared._database_epoch_ns(context.database_now)
        profile.require(claim["issued_at_epoch_ns"] <= now < claim["expires_at_epoch_ns"])
        shared._require_role(context, subject_id=values["actor_id"], required_role="policy_publisher")
        actual = originals.original_context(context, bound, request)
        assignment, artifact, handoff, key, attestation = (actual[name] for name in ("assignment", "artifact", "handoff", "key", "attestation"))
        exact = {"candidate_id": bound["candidateId"], "canary_id": bound["canaryId"], "instance_id": bound["instanceId"],
            "boot_id": bound["bootId"], "member_id": actual["member"]["member_id"], "member_ordinal": bound["memberOrdinal"],
            "load_receipt_envelope_digest": bound["loadReceiptEnvelopeDigest"],
            "load_receipt_payload_digest": actual["load"]["load_receipt_payload_digest"],
            "candidate_policy_hash": artifact["policy_hash"], "candidate_policy_bundle_digest": actual["candidate_bundle_digest"],
            "candidate_policy_sequence": assignment["candidate_policy_sequence"], "candidate_rollback_epoch": assignment["candidate_rollback_epoch"],
            "active_policy_hash": actual["active"]["policy_hash"], "active_policy_sequence": actual["active"]["sequence"],
            "active_rollback_epoch": actual["active"]["rollback_epoch"], "active_policy_bundle_digest": actual["active_bundle_digest"],
            "runtime_executable_digest": assignment["runtime_digest"], "attestation_mode": attestation["tee_platform"],
            "runtime_attestation_receipt_envelope_digest": attestation["attestation_receipt_envelope_digest"],
            "runtime_attestation_receipt_payload_digest": attestation["attestation_receipt_payload_digest"],
            "attestation_role_authorization_digest": handoff["role_authorization_envelope_digest"],
            "attestation_evidence_digest": attestation["tee_evidence_digest"], "tee_measurement_digest": attestation["tee_measurement_digest"],
            "signing_key_id": handoff["shadow_signing_key_id"], "attestation_chain_digest": handoff["attestation_chain_digest"]}
        exact.update({field: assignment[field] for field in ("assignment_envelope_digest", "assignment_payload_digest",
            "assignment_revision", "generation_epoch", "minimum_generation_tombstone_epoch", "fleet_id", "membership_revision", "membership_root_digest")})
        exact.update({field: handoff[field] for field in ("runtime_release_digest", "runtime_config_digest", "runtime_policy_digest",
            "attestation_policy_digest", "attestation_trust_checkpoint_digest")})
        profile.require(all(item[field] == value for field, value in exact.items()), "generation publication predecessor changed")
        item["runtime_attestation_verification_receipt_digest"] = attestation["verification_receipt_digest"]
        custody, ingress = db._policy_shadow_generation_high_water_digests(item)
        profile.require(item["custody_high_water_digest"] == custody and item["ingress_high_water_digest"] == ingress)
        identity = profile.generation_identity(actor=values["actor_id"], bound=bound, request=request, originals=actual)
        profile.require(identity["requestIdentitySha256"] == claim["request_identity_digest"])
        aliases = ("request_id", "replay_id", "management_handoff_id", "generation_id_digest",
            "generation_publication_envelope_digest", "generation_publication_payload_digest")
        previous = originals.population(context, "policy_shadow_generation_publications")
        profile.require(len(previous) < 32 and not any(any(row[field] == item[field] for field in aliases) for row in previous),
            "generation publication is already committed or conflicting; lookup never reenters contact")
        profile.require(len(originals.population(context, "policy_authority_evidence_verifications")) <= 30,
            "candidate verification history capacity cannot admit both originals")
        verification_mutations = []
        verified = []
        for evidence in evidence_inputs(item, projection):
            given = values["request"]["verificationInputs"][evidence["evidence_kind"]]
            receipt, mutation = trust.current(context, **evidence, expected_key=given["key"], expected_head=given["head"],
                expected_sequence=given["revocationSequence"])
            verified.append(receipt)
            if mutation is not None:
                verification_mutations.append(mutation)
        inner, publication = verified
        item["runtime_attestation_verifier_record_binding_digest"] = inner["record_binding_digest"]
        item["rust_attestation_verification_receipt_digest"] = inner["verification_receipt_digest"]
        item.update({field: publication[field] for field in ("evidence_kind", "record_binding_digest", "verification_receipt_digest")})
        profile.require(publication["public_key_digest"] == key["public_key_digest"]
            and publication["issued_at_epoch_ns"] == projection["evidence"]["issuedAtUnixNanos"]
            and publication["expires_at_epoch_ns"] == projection["evidence"]["expiresAtUnixNanos"])
        stage = audit_stage(values, item, projection, context.database_now)
        row = {column: item[column] for column in db._POLICY_SHADOW_GENERATION_PUBLICATION_COLUMNS
            if column not in {"management_request_json", "created_transition_digest"}}
        row.update(management_request_json=claim["management_request_json"], created_transition_digest=stage["transition"]["transition_digest"])
        mutations = list(verification_mutations)
        for table, key_fields, value in (("policy_shadow_generation_publications", {
                    "generation_publication_envelope_digest": row["generation_publication_envelope_digest"]}, row),
                ("policy_authority_transition_audits", {"transition_digest": row["created_transition_digest"]}, stage["transition"]),
                ("metadata_audit_outbox", {"id": stage["outbox"]["id"]}, stage["outbox"])):
            selected = context.exact(table, key_fields)
            profile.require(not selected["present"])
            mutations.append(core.mutation(operation=self.operation, selected=selected, row=value))
        mutations.append(core.mutation(operation=self.operation, selected=selected_claim,
            row={**claim, "publication_envelope_digest": row["generation_publication_envelope_digest"]}))
        return core.KernelTransition(mutations=tuple(mutations), result={"ok": True, "operation": self.operation,
            "requestDigest": context.request_digest, "auditEventDigest": stage["outbox"]["event_digest"],
            "idempotentReplay": False, "publication": row}, work_units=2048)
