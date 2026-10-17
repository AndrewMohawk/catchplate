from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping

from catchplate import authority_contract
from catchplate import authority_transition_core as core


_TRUST_ERROR_FIELDS = frozenset({"publication_id", "error"})
_SIGNED_BIGINT_MAX = 2**63 - 1
_DECISION_GATE_BINDING_FIELDS = frozenset(
    {
        "publicationRequestId",
        "replayId",
        "generationId",
        "predecessorGenerationDigest",
        "generationEpoch",
        "generationTombstoneEpoch",
        "assignmentEnvelopeDigest",
        "assignmentPayloadDigest",
        "assignmentRevision",
        "loadReceiptEnvelopeDigest",
        "loadReceiptPayloadDigest",
        "custodyPreparationReceiptDigest",
        "custodyPublicationReceiptDigest",
        "activationPublicationReceiptDigest",
        "ingressEvidenceChainDigest",
        "ingressHighWaterDigest",
        "ingressRangeStartSequence",
        "ingressRangeEndSequence",
        "ingressRangePredecessorHeadDigest",
        "activationMode",
        "activePolicyDigest",
        "activePolicySequence",
        "activeRollbackEpoch",
        "activeCompiledSnapshotDigest",
        "candidatePolicyDigest",
        "candidatePolicySequence",
        "candidateRollbackEpoch",
        "candidateCompiledSnapshotDigest",
        "publicationRevision",
        "policyHighWaterBeforeDigest",
        "policyHighWaterAfterDigest",
        "readinessCoreDigest",
        "authorityKeyIndependenceDigest",
        "activationTransactionDigest",
        "runtimeExecutableDigest",
        "runtimeReleaseAttestationDigest",
        "runtimePolicyAttestationDigest",
        "runtimeConfigAttestationDigest",
        "runtimeTeeEvidenceDigest",
        "runtimeTeeMeasurementDigest",
        "runtimeAttestationReceiptDigest",
        "runtimeEvidenceChainDigest",
        "bootIdDigest",
        "instanceId",
        "trustCheckpointDigest",
        "trustRevocationGeneration",
        "trustRevocationRootDigest",
        "persistenceReceiptDigest",
        "retrievalIdDigest",
        "retrievalProofDigest",
        "authoritativeLedgerEventOrdinal",
        "authoritativeLedgerHeadDigest",
        "authoritativeSpoolRootDigest",
    }
)
_ACTIVATION_ATTEMPT_FIELDS = frozenset(
    {
        "activation_attempt_id",
        "readiness_envelope_digest",
        "readiness_payload_digest",
        "readiness_core_digest",
        "assignment_envelope_digest",
        "assignment_payload_digest",
        "compiler_analysis_payload_digest",
        "approval_context_digest",
        "approval_mode",
        "required_approval_quorum",
        "expansion_cells_digest",
        "publication_revision",
        "expected_high_water_digest",
        "approval_id",
        "canary_id",
        "artifact_envelope_digest",
        "artifact_payload_digest",
        "candidate_policy_hash",
        "candidate_policy_sequence",
        "candidate_rollback_epoch",
        "predecessor_policy_hash",
        "expected_active_policy_sequence",
        "expected_active_rollback_epoch",
        "activation_mode",
        "rollback_authorization_digest",
        "activation_intent_digest",
        "publication_intent_digest",
        "activation_request_envelope_digest",
        "activation_request_payload_digest",
        "activation_request_envelope_json",
        "activation_request_payload_json",
        "requested_by",
        "created_at_epoch_ns",
        "expires_at_epoch_ns",
    }
)
_ACTIVATION_CONSUMPTION_FIELDS = frozenset(
    {
        "approval_id",
        "activation_attempt_id",
        "consumption_digest",
        "consumed_by",
        "consumed_at",
        "member_count",
    }
)
_ACTIVATION_PUBLICATION_RECEIPT_FIELDS = frozenset(
    {
        "publication_receipt_envelope_digest",
        "publication_receipt_payload_digest",
        "activation_attempt_id",
        "readiness_payload_digest",
        "readiness_core_digest",
        "assignment_envelope_digest",
        "assignment_payload_digest",
        "compiler_analysis_payload_digest",
        "approval_id",
        "approval_context_digest",
        "approval_mode",
        "required_approval_quorum",
        "expansion_cells_digest",
        "activation_mode",
        "rollback_authorization_payload_digest",
        "publication_revision",
        "publication_intent_digest",
        "committed_activation_revision",
        "committed_activation_state_digest",
        "expected_canary_activating_state_digest",
        "expected_canary_active_state_digest",
        "policy_publication_hash",
        "publication_status",
        "scope",
        "policy_id",
        "committed_policy_sequence",
        "committed_rollback_epoch",
        "committed_policy_hash",
        "previous_policy_hash",
        "high_water_before_digest",
        "high_water_after_digest",
        "publication_receipt_envelope_json",
        "publication_receipt_payload_json",
        "signature_algorithm",
        "signing_key_id",
        "signature",
        "signature_digest",
        "publisher_id",
        "committed_at_epoch_ns",
    }
)
_ACTIVATION_REVISION_FIELDS = frozenset(
    {
        "activation_attempt_id",
        "revision",
        "status",
        "previous_revision",
        "previous_status",
        "previous_state_digest",
        "approval_id",
        "approval_consumption_digest",
        "publication_intent_digest",
        "uncertainty_digest",
        "state_envelope_json",
        "state_payload_json",
        "state_digest",
        "signature_algorithm",
        "signing_key_id",
        "signature",
        "signature_digest",
        "created_at_epoch_ns",
        "approved_at_epoch_ns",
        "published_at_epoch_ns",
        "terminal_from_status",
        "terminal_at_epoch_ns",
        "actor_id",
        "event_type",
    }
)
_CANARY_REVISION_FIELDS = frozenset(
    {
        "canary_id",
        "revision",
        "status",
        "previous_revision",
        "previous_status",
        "previous_state_digest",
        "assignment_envelope_digest",
        "assignment_payload_digest",
        "sealed_checkpoint_root_digest",
        "sealed_instance_set_digest",
        "readiness_envelope_digest",
        "readiness_payload_digest",
        "state_envelope_json",
        "state_payload_json",
        "state_digest",
        "signature_algorithm",
        "signing_key_id",
        "signature",
        "signature_digest",
        "created_at_epoch_ns",
        "observation_started_at_epoch_ns",
        "sealed_at_epoch_ns",
        "terminal_from_status",
        "terminal_at_epoch_ns",
        "actor_id",
        "event_type",
    }
)
_ACTIVATION_PREPARE_FIELDS = frozenset(
    {
        "activation",
        "approval",
        "approvalMembers",
        "approvalConsumption",
        "activationRevisions",
        "canaryRevisions",
        "publicationReceipt",
        "generationPublicationEnvelopeDigest",
        "decisionGateEvidenceDigest",
        "policySignatureEvidenceDigest",
    }
)
_ACTIVATION_RECORD_INCLUSION_FIELDS = frozenset(
    {
        "preparationDigest",
        "inclusions",
        "auditStoreIdentityDigest",
        "generationPublicationEnvelopeDigest",
        "decisionGateEvidenceDigest",
    }
)
_ACTIVATION_FINALIZE_FIELDS = frozenset(
    {
        "preparationDigest",
        "inclusionReceiptEnvelopeDigests",
        "activationAttemptId",
        "canaryId",
        "activationRevisionNumbers",
        "canaryRevisionNumbers",
        "controlPlaneApprovalIds",
        "approverIds",
        "requesterId",
        "publicationReceiptEnvelopeDigest",
        "rollbackAuthorizationDigest",
    }
)
_ACTIVATION_ABORT_FIELDS = frozenset(
    {
        "preparationDigest",
        "reason",
        "abortedBy",
    }
)
_GENESIS_PREPARE_FIELDS = frozenset(
    {
        "record",
        "policySignatureEvidenceDigest",
    }
)
_GENESIS_RECORD_FIELDS = frozenset(
    {
        "genesis_preparation_digest",
        "policy_id",
        "policy_sequence",
        "rollback_epoch",
        "policy_hash",
        "high_water_digest",
        "genesis_envelope_json",
        "genesis_envelope_digest",
        "genesis_payload_json",
        "genesis_payload_digest",
        "signature_algorithm",
        "signing_key_id",
        "signature",
        "signature_digest",
        "prepared_by",
        "prepared_at_epoch_ns",
        "expires_at_epoch_ns",
    }
)
_GENESIS_FINALIZE_FIELDS = frozenset(
    {
        "genesisPreparationDigest",
        "inclusionReceipt",
        "inclusionEvidenceDigest",
        "auditStoreIdentityDigest",
    }
)
_ACTIVATION_PREPARATION_INPUT_FIELDS = frozenset(
    {
        "schema",
        "activation",
        "approval",
        "approvalMembers",
        "approvalConsumption",
        "activationRevisions",
        "canaryRevisions",
        "publicationReceipt",
        "generationPublicationEnvelopeDigest",
        "decisionGateEvidenceDigest",
    }
)
_AUDIT_EVENT_COUNTS = MappingProxyType(
    {
        "policy.activation.prepare": 7,
        "policy.genesis.prepare": 1,
        "rbac.binding.mutate": 1,
        "policy.activation.abort": 1,
    }
)
_VALID_RBAC_ROLES = frozenset(
    {
        "admin",
        "approver",
        "attestation_operator",
        "attestation_reviewer",
        "auditor",
        "credential_owner",
        "policy_author",
        "policy_publisher",
    }
)
_RBAC_MUTATE_FIELDS = frozenset(
    {
        "subjectId",
        "roles",
        "status",
        "expectedGeneration",
        "actorId",
        "reason",
        "eventType",
        "event",
    }
)
_WEBAUTHN_CREDENTIAL_INPUT_FIELDS = frozenset(
    {
        "credential_id",
        "user_id",
        "label",
        "public_key_cose",
        "sign_count",
        "aaguid",
        "authenticator_class",
        "attestation_fmt",
        "attestation_trusted",
        "attestation_trust_path",
        "attestation_leaf_sha256",
        "attestation_root_sha256",
        "attestation_trust_bundle_digest",
        "attestation_trust_bundle_sequence",
        "attestation_verified_at",
        "transports",
        "dev_private_key_pem",
    }
)
_WEBAUTHN_COUNTER_FIELDS = frozenset(
    {
        "recordId",
        "credentialId",
        "expectedSignCount",
        "newSignCount",
    }
)
_POLICY_EXPORT_FREEZE_FIELDS = frozenset(
    {"activation_attempt_id"}
)
_POLICY_EXPORT_AUTHORIZE_FIELDS = frozenset(
    {
        "export_id",
        "expected_authorization_revision",
        "requested_expires_at_epoch_ns",
        "page_ordinals",
    }
)
_POLICY_EXPORT_FINALIZE_FIELDS = frozenset(
    {
        "export_id",
        "issuance_evidence",
        "page_evidence",
    }
)
_POLICY_EXPORT_EVIDENCE_FIELDS = frozenset(
    {
        "assignment_envelope_digest",
        "member_ordinal",
        "canary_id",
        "fleet_id",
        "membership_revision",
        "instance_id",
        "boot_id",
        "envelope_json",
        "envelope_digest",
        "payload_json",
        "payload_digest",
        "signature_algorithm",
        "signing_key_id",
        "signature",
        "signature_digest",
        "record_binding_digest",
        "verification_receipt_digest",
        "issued_at_epoch_ns",
        "expires_at_epoch_ns",
    }
)
_POLICY_EXPORT_PAGE_EVIDENCE_FIELDS = (
    _POLICY_EXPORT_EVIDENCE_FIELDS | {"page_ordinal"}
)
_WEBAUTHN_TRUST_STAGE_FIELDS = frozenset(
    {
        "previous_bundle_digest",
        "bundle_digest",
        "sequence",
        "rollback_epoch",
        "signing_key_id",
        "bundle",
        "payload_digest",
        "actor_id",
        "withdrawn_credential_ids",
        "query_hints",
        "reason",
        "approval_id",
        "audit_event",
    }
)
_WEBAUTHN_TRUST_COMPLETE_FIELDS = frozenset(
    {
        "publication_id",
        "verification_evidence_digest",
    }
)
_WEBAUTHN_TRUST_VERIFICATION_FIELDS = frozenset(
    {
        "schema",
        "publicationId",
        "bundleDigest",
        "payloadDigest",
        "sequence",
        "rollbackEpoch",
        "signingKeyId",
        "canonicalEnvelopeDigest",
        "signatureAlgorithm",
        "signatureDigest",
        "verifierIdentityDigest",
        "verifierMeasurementDigest",
        "verifierAttestationReceiptDigest",
        "witnessReceiptDigest",
        "witnessSequence",
        "issuedAtEpochNs",
        "expiresAtEpochNs",
        "verifiedAtEpochNs",
    }
)
_WEBAUTHN_REGISTRATION_FINALIZE_FIELDS = frozenset(
    {
        "challenge_id",
        "challenge",
        "user_id",
        "credential_id",
        "label",
        "public_key_cose",
        "sign_count",
        "aaguid",
        "authenticator_class",
        "attestation_fmt",
        "attestation_trusted",
        "attestation_trust_path",
        "attestation_leaf_sha256",
        "attestation_root_sha256",
        "attestation_trust_bundle_digest",
        "attestation_trust_bundle_sequence",
        "attestation_verified_at",
        "transports",
        "attestation_evidence_digest",
        "oidc_session_id",
        "sibling_challenge_ids",
    }
)
_WEBAUTHN_REGISTRATION_VERIFICATION_FIELDS = frozenset(
    {
        "schema",
        "challengeId",
        "challengeDigest",
        "userId",
        "credentialIdDigest",
        "publicKeyCoseDigest",
        "signCount",
        "aaguid",
        "authenticatorClass",
        "attestationFormat",
        "attestationTrusted",
        "attestationLeafSha256",
        "attestationRootSha256",
        "trustBundleDigest",
        "trustBundleSequence",
        "clientDataDigest",
        "attestationObjectDigest",
        "verificationReceiptDigest",
        "signatureAlgorithm",
        "signatureDigest",
        "verifierIdentityDigest",
        "verifierMeasurementDigest",
        "verifierAttestationReceiptDigest",
        "issuedAtEpochNs",
        "expiresAtEpochNs",
        "verifiedAtEpochNs",
    }
)
_WEBAUTHN_REVOKE_FIELDS = frozenset(
    {
        "record_id",
        "actor_id",
        "reason",
        "source",
        "audit_event",
        "approval_grant_ids",
        "control_plane_approval_ids",
        "oidc_session_ids",
        "registration_challenge_ids",
    }
)
_POLICY_EXPORT_MAX_PAGES = 32
_WEBAUTHN_EXACT_CASCADE_MAX = 32


def _bounded_string(
    value: Any,
    label: str,
    *,
    maximum_bytes: int,
) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > maximum_bytes
    ):
        raise core.TransitionKernelError(f"{label} is not a bounded string")
    return value


def _row(selected: Mapping[str, Any]) -> dict[str, Any]:
    value = selected.get("row")
    if not isinstance(value, Mapping):
        raise core.TransitionKernelError(
            "authority transition selected row is invalid"
        )
    return dict(value)


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _database_epoch_ns(value: datetime) -> int:
    normalized = value.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = normalized - epoch
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1_000
    )


def _database_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _mapping(
    value: Any,
    label: str,
    *,
    fields: frozenset[str] | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or fields is not None and set(value) != fields
    ):
        raise core.TransitionKernelError(f"{label} is not an exact object")
    result = dict(value)
    core.canonical_bytes(result)
    return result


def _mapping_json(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise core.TransitionKernelError(f"{label} is not canonical JSON")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise core.TransitionKernelError(
            f"{label} is not canonical JSON"
        ) from exc
    if (
        not isinstance(parsed, Mapping)
        or core.canonical_bytes(parsed).decode("ascii") != value
    ):
        raise core.TransitionKernelError(f"{label} is not canonical JSON")
    return dict(parsed)


def _list(
    value: Any,
    label: str,
    *,
    maximum: int,
) -> list[Any]:
    if (
        not isinstance(value, list)
        or len(value) > maximum
    ):
        raise core.TransitionKernelError(f"{label} exceeds its bound")
    core.canonical_bytes(value)
    return list(value)


def _exact_query(
    *,
    operation: str,
    name: str,
    table: str,
    key: Mapping[str, Any],
) -> core.BoundedQuery:
    exact_key = dict(key)
    return core.BoundedQuery(
        query_id=core.query_program_id(operation, name, table),
        table=table,
        predicates=tuple(
            core.QueryPredicate(column, "eq", value)
            for column, value in sorted(exact_key.items())
        ),
        order_by=tuple(
            core.QueryOrder(column)
            for column in sorted(exact_key)
        ),
        maximum_rows=1,
        absent_key=exact_key,
    )


def _exact_empty_page_query(
    *,
    operation: str,
    name: str,
    table: str,
    predicates: Mapping[str, Any],
    order_by: tuple[str, ...],
) -> core.BoundedQuery:
    return core.BoundedQuery(
        query_id=core.query_program_id(operation, name, table),
        table=table,
        predicates=tuple(
            core.QueryPredicate(column, "eq", value)
            for column, value in sorted(predicates.items())
        ),
        order_by=tuple(
            core.QueryOrder(column) for column in order_by
        ),
        maximum_rows=1,
        proof_primitive="ordered-exact-page",
        exact_page=True,
    )


def _operation_id(operation: str, request_digest: str) -> str:
    return core.framed_digest(
        "catchplate.policyAuthorityOperation/v2",
        operation.encode("utf-8"),
        request_digest.encode("utf-8"),
    )


def _immutable_mutation(
    context: core.KernelContext,
    *,
    table: str,
    key: Mapping[str, Any],
    row: Mapping[str, Any],
) -> dict[str, Any] | None:
    selected = context.exact(table, key)
    if selected.get("present") is True:
        if _row(selected) != dict(row):
            raise core.TransitionKernelError(
                f"immutable {table} identity was reused"
            )
        return None
    return core.mutation(
        operation=context.operation,
        selected=selected,
        row=row,
    )


def _external_statement(
    context: core.KernelContext,
    *,
    evidence_type: str,
    evidence_digest: str,
    binding_domain: str,
    consumed_operation_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    selected = context.exact(
        "policy_authority_external_evidence_receipts",
        {"evidence_digest": evidence_digest},
    )
    raw = _row(selected)
    statement = _mapping_json(
        raw.get("statement_json"),
        f"{evidence_type} statement",
    )
    binding_digest = core.framed_digest(
        binding_domain,
        core.canonical_bytes(statement),
    )
    if raw.get("binding_digest") != binding_digest:
        raise core.TransitionKernelError(
            f"{evidence_type} binding is not canonical"
        )
    verified = (
        context.evidence(
            evidence_type=evidence_type,
            evidence_digest=evidence_digest,
            binding_digest=binding_digest,
        )
        if consumed_operation_id is None
        else context.consumed_evidence(
            evidence_type=evidence_type,
            evidence_digest=evidence_digest,
            binding_digest=binding_digest,
            consumed_operation_id=consumed_operation_id,
        )
    )
    return verified, statement, binding_digest


def _decision_gate_statement(
    context: core.KernelContext,
    evidence_digest: str,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    selected = context.exact(
        "policy_authority_external_evidence_receipts",
        {"evidence_digest": evidence_digest},
    )
    raw = _row(selected)
    statement = _mapping_json(
        raw.get("statement_json"),
        "decision-gate publication statement",
    )
    if not _DECISION_GATE_BINDING_FIELDS <= set(statement):
        raise core.TransitionKernelError(
            "decision-gate publication statement is incomplete"
        )
    binding = {
        field: statement[field]
        for field in _DECISION_GATE_BINDING_FIELDS
    }
    context.decision_gate_publication_evidence(
        evidence_digest=evidence_digest,
        expected_binding=binding,
    )
    binding_digest = core.framed_digest(
        "catchplate.policyAuthorityDecisionGatePublicationBinding/v1",
        core.canonical_bytes(binding),
    )
    return statement, binding, binding_digest


def _consumed_decision_gate_statement(
    context: core.KernelContext,
    *,
    evidence_digest: str,
    consumed_operation_id: str,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    selected = context.exact(
        "policy_authority_external_evidence_receipts",
        {"evidence_digest": evidence_digest},
    )
    raw = _row(selected)
    statement = _mapping_json(
        raw.get("statement_json"),
        "consumed decision-gate publication statement",
    )
    if not _DECISION_GATE_BINDING_FIELDS <= set(statement):
        raise core.TransitionKernelError(
            "consumed decision-gate publication statement is incomplete"
        )
    binding = {
        field: statement[field]
        for field in _DECISION_GATE_BINDING_FIELDS
    }
    context.consumed_decision_gate_publication_evidence(
        evidence_digest=evidence_digest,
        expected_binding=binding,
        consumed_operation_id=consumed_operation_id,
    )
    binding_digest = core.framed_digest(
        "catchplate.policyAuthorityDecisionGatePublicationBinding/v1",
        core.canonical_bytes(binding),
    )
    return statement, binding, binding_digest


def _validate_generation_binding(
    generation: Mapping[str, Any],
    binding: Mapping[str, Any],
    activation: Mapping[str, Any],
) -> None:
    exact = {
        "publicationRequestId": generation.get("request_id"),
        "replayId": generation.get("replay_id"),
        "generationId": generation.get("generation_id_digest"),
        "generationEpoch": generation.get("generation_epoch"),
        "generationTombstoneEpoch":
            generation.get("minimum_generation_tombstone_epoch"),
        "assignmentEnvelopeDigest":
            generation.get("assignment_envelope_digest"),
        "assignmentPayloadDigest":
            generation.get("assignment_payload_digest"),
        "assignmentRevision": generation.get("assignment_revision"),
        "loadReceiptEnvelopeDigest":
            generation.get("load_receipt_envelope_digest"),
        "loadReceiptPayloadDigest":
            generation.get("load_receipt_payload_digest"),
        "custodyPreparationReceiptDigest":
            generation.get("custody_preparation_receipt_digest"),
        "ingressHighWaterDigest":
            generation.get("ingress_high_water_digest"),
        "activePolicyDigest": generation.get("active_policy_hash"),
        "activePolicySequence": generation.get("active_policy_sequence"),
        "activeRollbackEpoch": generation.get("active_rollback_epoch"),
        "activeCompiledSnapshotDigest":
            generation.get("active_policy_bundle_digest"),
        "candidatePolicyDigest": generation.get("candidate_policy_hash"),
        "candidatePolicySequence":
            generation.get("candidate_policy_sequence"),
        "candidateRollbackEpoch":
            generation.get("candidate_rollback_epoch"),
        "candidateCompiledSnapshotDigest":
            generation.get("candidate_policy_bundle_digest"),
        "publicationRevision":
            generation.get("publication_revision"),
        "runtimeExecutableDigest":
            generation.get("runtime_executable_digest"),
        "runtimeReleaseAttestationDigest":
            generation.get("runtime_release_digest"),
        "runtimePolicyAttestationDigest":
            generation.get("runtime_policy_digest"),
        "runtimeConfigAttestationDigest":
            generation.get("runtime_config_digest"),
        "runtimeTeeEvidenceDigest":
            generation.get("attestation_evidence_digest"),
        "runtimeTeeMeasurementDigest":
            generation.get("tee_measurement_digest"),
        "runtimeAttestationReceiptDigest":
            generation.get(
                "runtime_attestation_receipt_envelope_digest"
            ),
        "runtimeEvidenceChainDigest":
            generation.get("attestation_chain_digest"),
        "bootIdDigest": generation.get("boot_id"),
        "instanceId": generation.get("instance_id"),
        "trustCheckpointDigest":
            generation.get("attestation_trust_checkpoint_digest"),
    }
    activation_exact = {
        "activationMode": str(
            activation.get("activation_mode")
        ).replace("_", "-"),
        "activePolicyDigest":
            activation.get("predecessor_policy_hash"),
        "activePolicySequence":
            activation.get("expected_active_policy_sequence"),
        "activeRollbackEpoch":
            activation.get("expected_active_rollback_epoch"),
        "candidatePolicyDigest":
            activation.get("candidate_policy_hash"),
        "candidatePolicySequence":
            activation.get("candidate_policy_sequence"),
        "candidateRollbackEpoch":
            activation.get("candidate_rollback_epoch"),
        "publicationRevision":
            activation.get("publication_revision"),
        "policyHighWaterBeforeDigest":
            activation.get("expected_high_water_digest"),
        "readinessCoreDigest":
            activation.get("readiness_core_digest"),
        "assignmentEnvelopeDigest":
            activation.get("assignment_envelope_digest"),
        "assignmentPayloadDigest":
            activation.get("assignment_payload_digest"),
    }
    if (
        generation.get("hardware_attested") is not True
        or any(binding.get(field) != value for field, value in exact.items())
        or any(
            binding.get(field) != value
            for field, value in activation_exact.items()
        )
    ):
        raise core.TransitionKernelError(
            "decision-gate evidence diverges from activation authority"
        )


def _validate_activation_publication_projection(
    *,
    receipt: Mapping[str, Any],
    activation: Mapping[str, Any],
    activation_revisions: list[dict[str, Any]],
    canary_revisions: list[dict[str, Any]],
    decision_statement: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> None:
    wire = _mapping(
        decision_statement.get("activationPublicationEnvelope"),
        "activation custody publication wire",
    )
    envelope = _mapping_json(
        receipt.get("publication_receipt_envelope_json"),
        "activation publication receipt envelope",
    )
    payload = _mapping_json(
        receipt.get("publication_receipt_payload_json"),
        "activation publication receipt payload",
    )
    exact = {
        "publication_receipt_envelope_digest":
            decision_statement[
                "activationPublicationEnvelopeDigest"
            ],
        "publication_receipt_payload_digest":
            decision_statement[
                "activationPublicationEnvelopeDigest"
            ],
        "activation_attempt_id":
            activation["activation_attempt_id"],
        "readiness_payload_digest":
            activation["readiness_payload_digest"],
        "readiness_core_digest":
            activation["readiness_core_digest"],
        "assignment_envelope_digest":
            activation["assignment_envelope_digest"],
        "assignment_payload_digest":
            activation["assignment_payload_digest"],
        "compiler_analysis_payload_digest":
            activation["compiler_analysis_payload_digest"],
        "approval_id": activation["approval_id"],
        "approval_context_digest":
            activation["approval_context_digest"],
        "approval_mode": activation["approval_mode"],
        "required_approval_quorum":
            activation["required_approval_quorum"],
        "expansion_cells_digest":
            activation["expansion_cells_digest"],
        "activation_mode": activation["activation_mode"],
        "rollback_authorization_payload_digest":
            activation["rollback_authorization_digest"],
        "publication_revision":
            activation["publication_revision"],
        "publication_intent_digest":
            activation["publication_intent_digest"],
        "committed_activation_revision":
            activation_revisions[3]["revision"],
        "committed_activation_state_digest":
            activation_revisions[3]["state_digest"],
        "expected_canary_activating_state_digest":
            canary_revisions[0]["state_digest"],
        "expected_canary_active_state_digest":
            canary_revisions[1]["state_digest"],
        "policy_publication_hash":
            activation["candidate_policy_hash"],
        "publication_status": "committed",
        "scope": "active",
        "committed_policy_sequence":
            activation["candidate_policy_sequence"],
        "committed_rollback_epoch":
            activation["candidate_rollback_epoch"],
        "committed_policy_hash":
            activation["candidate_policy_hash"],
        "previous_policy_hash":
            activation["predecessor_policy_hash"],
        "high_water_before_digest":
            binding["policyHighWaterBeforeDigest"],
        "high_water_after_digest":
            binding["policyHighWaterAfterDigest"],
        "signature_algorithm": "Ed25519",
        "signing_key_id": wire["signingKeyId"],
        "signature": wire["signature"],
        "signature_digest": wire["signedReceiptSha256"],
        "publisher_id": activation["requested_by"],
        "committed_at_epoch_ns":
            wire["trustedObservedAtUnixNanos"],
    }
    if (
        envelope != wire
        or payload != wire
        or _sha256(core.canonical_bytes(wire))
            != decision_statement[
                "activationPublicationEnvelopeDigest"
            ]
        or any(receipt.get(field) != value for field, value in exact.items())
        or receipt.get("policy_id") in {None, ""}
    ):
        raise core.TransitionKernelError(
            "activation publication projection diverges from custody wire"
        )


def _validated_input_evidence(
    context: core.KernelContext,
    *,
    evidence_digest: str,
    input_digest: str,
    subject_digest: str,
    consumed_operation_id: str | None = None,
) -> tuple[dict[str, Any], str]:
    _, statement, binding_digest = _external_statement(
        context,
        evidence_type="policy-signature-verification/v1",
        evidence_digest=evidence_digest,
        binding_domain=(
            "catchplate.policyAuthorityVerifiedInputBinding/v1"
        ),
        consumed_operation_id=consumed_operation_id,
    )
    if (
        set(statement)
        != {
            "schema",
            "operation",
            "requestDigest",
            "inputDigest",
            "subjectDigest",
        }
        or statement.get("schema")
            != "catchplate.policyAuthorityVerifiedInput/v1"
        or statement.get("operation") != context.operation
        or statement.get("requestDigest") != context.request_digest
        or statement.get("inputDigest") != input_digest
        or statement.get("subjectDigest") != subject_digest
    ):
        raise core.TransitionKernelError(
            "policy signature verification evidence diverged"
        )
    return statement, binding_digest


def _audit_stage(
    *,
    event_type: str,
    entity_kind: str,
    entity_id: str,
    entity_revision: int,
    state_digest: str,
    previous_state_digest: str | None,
    actor_id: str,
    evidence: Mapping[str, Any],
    created_at_epoch_ns: int,
    created_at: str,
) -> dict[str, Any]:
    event = {
        "schema": "catchplate.policyAuthorityTransition/v2",
        "entityKind": entity_kind,
        "entityId": entity_id,
        "entityRevision": entity_revision,
        "stateDigest": state_digest,
        "previousStateDigest": previous_state_digest,
        "eventType": event_type,
        "evidence": dict(evidence),
    }
    event_json = core.canonical_bytes(event).decode("ascii")
    event_payload_digest = _sha256(event_json.encode("ascii"))
    outbox_material = {
        "eventPayloadDigest": event_payload_digest,
        "eventType": event_type,
        "entityKind": entity_kind,
        "entityId": entity_id,
        "entityRevision": entity_revision,
    }
    outbox_id = (
        "policy-authority:"
        + hashlib.sha256(core.canonical_bytes(outbox_material)).hexdigest()
    )
    outbox_event_digest = core.framed_digest(
        "catchplate.metadataAuditOutboxEvent/v1",
        event_json.encode("ascii"),
    )
    transition_material = {
        "actorId": actor_id,
        "createdAtEpochNs": created_at_epoch_ns,
        "entityId": entity_id,
        "entityKind": entity_kind,
        "entityRevision": entity_revision,
        "eventPayloadDigest": event_payload_digest,
        "eventType": event_type,
        "outboxId": outbox_id,
        "outboxEventDigest": outbox_event_digest,
        "previousStateDigest": previous_state_digest,
        "stateDigest": state_digest,
    }
    transition_digest = _sha256(
        core.canonical_bytes(transition_material)
    )
    return {
        "outbox": {
            "id": outbox_id,
            "event_type": event_type,
            "actor_type": "admin",
            "actor_id": actor_id,
            "event_json": event_json,
            "event_digest": outbox_event_digest,
            "storage_format_version": 2,
            "status": "pending",
            "claim_id": None,
            "claimed_at": None,
            "attempts": 0,
            "audited_at": None,
            "audit_event_hash": None,
            "last_error": None,
            "created_at": created_at,
        },
        "transition": {
            "transition_digest": transition_digest,
            "outbox_id": outbox_id,
            "outbox_event_json": event_json,
            "outbox_event_digest": outbox_event_digest,
            "event_type": event_type,
            "entity_kind": entity_kind,
            "entity_id": entity_id,
            "entity_revision": entity_revision,
            "state_digest": state_digest,
            "previous_state_digest": previous_state_digest,
            "event_payload_digest": event_payload_digest,
            "actor_id": actor_id,
            "created_at_epoch_ns": created_at_epoch_ns,
        },
    }


def _fresh_audit_mutations(
    context: core.KernelContext,
    *,
    operation_id: str,
    outbox_rows: tuple[Mapping[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    """Construct the fixed fresh audit INSERTs; the planner owns their count.

    Only fresh branches use this helper. Whole-operation replay is checked by
    each kernel before calling it; partial/orphan audit identity reuse is not
    an insert and must not be turned back into a pending audit. No kernel-local
    audit counter is selected or updated here. The shared planner must derive
    the global counter CAS from the complete business mutation list.
    """
    if (
        type(outbox_rows) is not tuple
        or len(outbox_rows) != _AUDIT_EVENT_COUNTS.get(context.operation)
    ):
        raise core.TransitionKernelError(
            "audit records differ from the source operation"
        )
    if (
        type(operation_id) is not str
        or operation_id != _operation_id(context.operation, context.request_digest)
    ):
        raise core.TransitionKernelError(
            "audit event identity differs from the source operation"
        )
    identities: set[str] = set()
    inserts: list[dict[str, Any]] = []
    for row in outbox_rows:
        if not isinstance(row, Mapping):
            raise core.TransitionKernelError(
                "audit records differ from the source operation"
            )
        identity = row.get("id")
        if (
            type(identity) is not str
            or not identity
            or len(identity) > 256
            or not identity.isascii()
            or identity in identities
            or type(row.get("status")) is not str
            or row["status"] != "pending"
        ):
            raise core.TransitionKernelError(
                "audit records differ from the source operation"
            )
        identities.add(identity)
        selected = context.exact("metadata_audit_outbox", {"id": identity})
        if (
            selected.get("present") is not False
            or "row" not in selected
            or selected["row"] is not None
        ):
            raise core.TransitionKernelError(
                "fresh audit identity is not proven absent"
            )
        inserts.append(
            core.mutation(
                operation=context.operation,
                selected=selected,
                row=row,
            )
        )
    return tuple(inserts)


def _activation_prepare_arguments(
    arguments: Mapping[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
    str,
    str,
    str,
    dict[str, Any],
    str,
]:
    core.require_exact_arguments(arguments, _ACTIVATION_PREPARE_FIELDS)
    activation = _mapping(
        arguments["activation"],
        "activation attempt",
        fields=_ACTIVATION_ATTEMPT_FIELDS,
    )
    approval = _mapping(
        arguments["approval"],
        "activation approval",
    )
    members = [
        _mapping(item, "activation approval member")
        for item in _list(
            arguments["approvalMembers"],
            "activation approval members",
            maximum=2,
        )
    ]
    consumption = _mapping(
        arguments["approvalConsumption"],
        "activation approval consumption",
        fields=_ACTIVATION_CONSUMPTION_FIELDS,
    )
    activation_revisions = [
        _mapping(
            item,
            "activation revision",
            fields=_ACTIVATION_REVISION_FIELDS,
        )
        for item in _list(
            arguments["activationRevisions"],
            "activation revisions",
            maximum=4,
        )
    ]
    canary_revisions = [
        _mapping(
            item,
            "canary revision",
            fields=_CANARY_REVISION_FIELDS,
        )
        for item in _list(
            arguments["canaryRevisions"],
            "canary revisions",
            maximum=2,
        )
    ]
    publication_receipt = _mapping(
        arguments["publicationReceipt"],
        "activation publication receipt",
        fields=_ACTIVATION_PUBLICATION_RECEIPT_FIELDS,
    )
    if (
        len(members)
            != core.require_integer(
                activation.get("required_approval_quorum"),
                "activation approval quorum",
                minimum=1,
                maximum=2,
            )
        or len(activation_revisions) != 4
        or [item.get("status") for item in activation_revisions]
            != ["prepared", "approved", "publishing", "committed"]
        or len(canary_revisions) != 2
        or [item.get("status") for item in canary_revisions]
            != ["activating", "active"]
        or any(
            item.get("activation_attempt_id")
                != activation.get("activation_attempt_id")
            for item in activation_revisions
        )
        or any(
            item.get("canary_id") != activation.get("canary_id")
            for item in canary_revisions
        )
    ):
        raise core.TransitionKernelError(
            "activation state sequence is not exact"
        )
    for index, member in enumerate(members, start=1):
        if (
            member.get("approval_id") != activation.get("approval_id")
            or member.get("member_ordinal") != index
        ):
            raise core.TransitionKernelError(
                "activation approval member sequence is not exact"
            )
    for revision in activation_revisions + canary_revisions:
        state_payload_json = revision.get("state_payload_json")
        if (
            not isinstance(state_payload_json, str)
            or _sha256(state_payload_json.encode("ascii"))
                != revision.get("state_digest")
        ):
            raise core.TransitionKernelError(
                "activation state payload digest changed"
            )
        core.require_text(
            revision.get("actor_id"),
            "activation revision actor",
            maximum_bytes=1024,
        )
        core.require_text(
            revision.get("event_type"),
            "activation revision event type",
            maximum_bytes=256,
        )
        core.require_integer(
            revision.get("revision"),
            "activation revision",
            minimum=1,
            maximum=_SIGNED_BIGINT_MAX,
        )
        core.require_integer(
            revision.get("created_at_epoch_ns"),
            "activation revision time",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        )
    mode = activation.get("activation_mode")
    if (
        mode not in {"forward", "authorized_rollback"}
        or mode == "forward"
        and (
            activation.get("rollback_authorization_digest") is not None
            or activation.get("candidate_policy_sequence")
                <= activation.get("expected_active_policy_sequence")
            or activation.get("candidate_rollback_epoch")
                != activation.get("expected_active_rollback_epoch")
        )
        or mode == "authorized_rollback"
        and (
            activation.get("rollback_authorization_digest") is None
            or activation.get("candidate_rollback_epoch")
                <= activation.get("expected_active_rollback_epoch")
        )
    ):
        raise core.TransitionKernelError(
            "activation monotonic transition is invalid"
        )
    created_at = core.require_integer(
        activation.get("created_at_epoch_ns"),
        "activation creation time",
        minimum=0,
        maximum=_SIGNED_BIGINT_MAX,
    )
    expires_at = core.require_integer(
        activation.get("expires_at_epoch_ns"),
        "activation expiry",
        minimum=1,
        maximum=_SIGNED_BIGINT_MAX,
    )
    if created_at >= expires_at:
        raise core.TransitionKernelError(
            "activation validity interval is invalid"
        )
    generation_envelope_digest = core.require_digest(
        arguments["generationPublicationEnvelopeDigest"],
        "generation publication envelope",
    )
    decision_gate_evidence_digest = core.require_digest(
        arguments["decisionGateEvidenceDigest"],
        "decision-gate evidence",
    )
    policy_signature_evidence_digest = core.require_digest(
        arguments["policySignatureEvidenceDigest"],
        "policy signature evidence",
    )
    input_material = {
        "schema": "catchplate.policyActivationPreparationInput/v2",
        "activation": activation,
        "approval": approval,
        "approvalMembers": members,
        "approvalConsumption": consumption,
        "activationRevisions": activation_revisions,
        "canaryRevisions": canary_revisions,
        "publicationReceipt": publication_receipt,
        "generationPublicationEnvelopeDigest":
            generation_envelope_digest,
        "decisionGateEvidenceDigest":
            decision_gate_evidence_digest,
    }
    input_json = core.canonical_bytes(input_material).decode("ascii")
    input_digest = core.framed_digest(
        "catchplate.policyActivationPreparationInput/v2",
        input_json.encode("ascii"),
    )
    return (
        activation,
        approval,
        members,
        consumption,
        activation_revisions,
        canary_revisions,
        publication_receipt,
        generation_envelope_digest,
        decision_gate_evidence_digest,
        policy_signature_evidence_digest,
        input_material,
        input_digest,
    )


def _activation_preparation_digest(
    *,
    request_digest: str,
    activation_attempt_id: str,
    input_digest: str,
) -> str:
    return core.framed_digest(
        "catchplate.policyActivationPreparation/v2",
        request_digest.encode("ascii"),
        activation_attempt_id.encode("utf-8"),
        input_digest.encode("ascii"),
    )


def _activation_stages(
    *,
    activation: Mapping[str, Any],
    activation_revisions: list[dict[str, Any]],
    canary_revisions: list[dict[str, Any]],
    decision_gate_evidence_digest: str,
    created_at: str,
) -> list[dict[str, Any]]:
    stage_requests: list[
        tuple[str, Mapping[str, Any], str, str, Mapping[str, Any]]
    ] = [
        (
            "activation_prepared",
            activation_revisions[0],
            "activation",
            str(activation["activation_attempt_id"]),
            {
                "status": activation_revisions[0]["status"],
                "approvalId": activation_revisions[0]["approval_id"],
                "publicationIntentDigest":
                    activation_revisions[0][
                        "publication_intent_digest"
                    ],
                "uncertaintyDigest":
                    activation_revisions[0]["uncertainty_digest"],
            },
        ),
        (
            "canary_activating",
            canary_revisions[0],
            "canary",
            str(activation["canary_id"]),
            {
                "status": canary_revisions[0]["status"],
                "assignmentPayloadDigest":
                    canary_revisions[0]["assignment_payload_digest"],
                "readinessPayloadDigest":
                    canary_revisions[0]["readiness_payload_digest"],
            },
        ),
        (
            "activation_approved",
            activation_revisions[1],
            "activation",
            str(activation["activation_attempt_id"]),
            {
                "status": activation_revisions[1]["status"],
                "approvalId": activation_revisions[1]["approval_id"],
                "publicationIntentDigest":
                    activation_revisions[1][
                        "publication_intent_digest"
                    ],
                "uncertaintyDigest":
                    activation_revisions[1]["uncertainty_digest"],
            },
        ),
        (
            "activation_publishing",
            activation_revisions[2],
            "activation",
            str(activation["activation_attempt_id"]),
            {
                "status": activation_revisions[2]["status"],
                "approvalId": activation_revisions[2]["approval_id"],
                "publicationIntentDigest":
                    activation_revisions[2][
                        "publication_intent_digest"
                    ],
                "uncertaintyDigest":
                    activation_revisions[2]["uncertainty_digest"],
            },
        ),
    ]
    stages = [
        {
            "purpose": purpose,
            **_audit_stage(
                event_type=str(revision["event_type"]),
                entity_kind=entity_kind,
                entity_id=entity_id,
                entity_revision=int(revision["revision"]),
                state_digest=core.require_digest(
                    revision["state_digest"],
                    "activation state",
                ),
                previous_state_digest=(
                    None
                    if revision["previous_state_digest"] is None
                    else core.require_digest(
                        revision["previous_state_digest"],
                        "activation predecessor state",
                    )
                ),
                actor_id=str(revision["actor_id"]),
                evidence=evidence,
                created_at_epoch_ns=int(
                    revision["created_at_epoch_ns"]
                ),
                created_at=created_at,
            ),
        }
        for purpose, revision, entity_kind, entity_id, evidence
        in stage_requests
    ]
    publication = _audit_stage(
        event_type="policy.activation_publication.committed",
        entity_kind="publication_receipt",
        entity_id=str(activation["activation_attempt_id"]),
        entity_revision=1,
        state_digest=decision_gate_evidence_digest,
        previous_state_digest=core.require_digest(
            activation["expected_high_water_digest"],
            "activation high-water predecessor",
        ),
        actor_id=str(activation["requested_by"]),
        evidence={
            "approvalId": activation["approval_id"],
            "candidatePolicyHash": activation["candidate_policy_hash"],
            "decisionGateEvidenceDigest":
                decision_gate_evidence_digest,
            "readinessPayloadDigest":
                activation["readiness_payload_digest"],
        },
        created_at_epoch_ns=int(activation["created_at_epoch_ns"]),
        created_at=created_at,
    )
    stages.append(
        {
            "purpose": "publication_committed",
            **publication,
        }
    )
    for purpose, revision, entity_kind, entity_id, evidence in (
        (
            "activation_committed",
            activation_revisions[3],
            "activation",
            str(activation["activation_attempt_id"]),
            {
                "status": activation_revisions[3]["status"],
                "approvalId": activation_revisions[3]["approval_id"],
                "publicationIntentDigest":
                    activation_revisions[3][
                        "publication_intent_digest"
                    ],
                "uncertaintyDigest":
                    activation_revisions[3]["uncertainty_digest"],
            },
        ),
        (
            "canary_active",
            canary_revisions[1],
            "canary",
            str(activation["canary_id"]),
            {
                "status": canary_revisions[1]["status"],
                "assignmentPayloadDigest":
                    canary_revisions[1]["assignment_payload_digest"],
                "readinessPayloadDigest":
                    canary_revisions[1]["readiness_payload_digest"],
            },
        ),
    ):
        stages.append(
            {
                "purpose": purpose,
                **_audit_stage(
                    event_type=str(revision["event_type"]),
                    entity_kind=entity_kind,
                    entity_id=entity_id,
                    entity_revision=int(revision["revision"]),
                    state_digest=core.require_digest(
                        revision["state_digest"],
                        "activation state",
                    ),
                    previous_state_digest=(
                        None
                        if revision["previous_state_digest"] is None
                        else core.require_digest(
                            revision["previous_state_digest"],
                            "activation predecessor state",
                        )
                    ),
                    actor_id=str(revision["actor_id"]),
                    evidence=evidence,
                    created_at_epoch_ns=int(
                        revision["created_at_epoch_ns"]
                    ),
                    created_at=created_at,
                ),
            }
        )
    return stages


@dataclass(frozen=True, slots=True)
class _PolicyActivationPrepareKernel:
    operation: str = "policy.activation.prepare"
    handler: str = "catchplate_policy_authority_prepare"
    # The verified existing-preparation replay returns no business mutations.
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "policy.activation.prepare",
        "catchplate_policy_authority_prepare",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        core.require_digest(
            request_digest,
            "activation preparation request digest",
        )
        (
            activation,
            _,
            members,
            _,
            activation_revisions,
            canary_revisions,
            _,
            generation_envelope_digest,
            decision_gate_evidence_digest,
            policy_signature_evidence_digest,
            _,
            input_digest,
        ) = _activation_prepare_arguments(arguments)
        attempt_id = core.require_text(
            activation["activation_attempt_id"],
            "activation attempt identity",
            maximum_bytes=256,
        )
        preparation_digest = _activation_preparation_digest(
            request_digest=request_digest,
            activation_attempt_id=attempt_id,
            input_digest=input_digest,
        )
        stages = _activation_stages(
            activation=activation,
            activation_revisions=activation_revisions,
            canary_revisions=canary_revisions,
            decision_gate_evidence_digest=
                decision_gate_evidence_digest,
            created_at=_database_iso(database_now),
        )
        queries: list[core.BoundedQuery] = [
            _exact_query(
                operation=self.operation,
                name="preparation",
                table="policy_activation_preparations",
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="activation_evidence_binding",
                table=(
                    "policy_authority_activation_evidence_bindings"
                ),
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="attempt",
                table="policy_activation_attempts",
                key={"activation_attempt_id": attempt_id},
            ),
            _exact_query(
                operation=self.operation,
                name="finalization",
                table="policy_activation_finalizations",
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="abort",
                table="policy_activation_aborts",
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="decision_evidence",
                table="policy_authority_external_evidence_receipts",
                key={"evidence_digest": decision_gate_evidence_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="signature_evidence",
                table="policy_authority_external_evidence_receipts",
                key={"evidence_digest": policy_signature_evidence_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="generation_publication",
                table="policy_shadow_generation_publications",
                key={
                    "generation_publication_envelope_digest":
                        generation_envelope_digest
                },
            ),
            _exact_query(
                operation=self.operation,
                name="candidate_artifact",
                table="policy_candidate_artifacts",
                key={
                    "artifact_envelope_digest":
                        activation["artifact_envelope_digest"]
                },
            ),
            _exact_query(
                operation=self.operation,
                name="approval",
                table="policy_activation_approvals",
                key={"approval_id": activation["approval_id"]},
            ),
            _exact_query(
                operation=self.operation,
                name="policy_high_water",
                table="policy_high_water",
                key={"scope": "active"},
            ),
        ]
        for index, member in enumerate(members, start=1):
            queries.append(
                _exact_query(
                    operation=self.operation,
                    name=f"approval_member_{index}",
                    table="policy_activation_approval_members",
                    key={
                        "approval_id": activation["approval_id"],
                        "member_ordinal": index,
                    },
                )
            )
        for ordinal, stage in enumerate(stages, start=1):
            queries.extend(
                (
                    _exact_query(
                        operation=self.operation,
                        name=f"prepared_transition_{ordinal}",
                        table="policy_activation_prepared_transitions",
                        key={
                            "preparation_digest": preparation_digest,
                            "transition_ordinal": ordinal,
                        },
                    ),
                    _exact_query(
                        operation=self.operation,
                        name=f"transition_audit_{ordinal}",
                        table="policy_authority_transition_audits",
                        key={
                            "transition_digest":
                                stage["transition"][
                                    "transition_digest"
                                ]
                        },
                    ),
                    _exact_query(
                        operation=self.operation,
                        name=f"audit_outbox_{ordinal}",
                        table="metadata_audit_outbox",
                        key={"id": stage["outbox"]["id"]},
                    ),
                )
            )
        return tuple(queries)

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        (
            activation,
            approval,
            members,
            consumption,
            activation_revisions,
            canary_revisions,
            publication_receipt,
            generation_envelope_digest,
            decision_gate_evidence_digest,
            policy_signature_evidence_digest,
            input_material,
            input_digest,
        ) = _activation_prepare_arguments(context.arguments)
        attempt_id = str(activation["activation_attempt_id"])
        operation_id = _operation_id(
            self.operation,
            context.request_digest,
        )
        preparation_digest = _activation_preparation_digest(
            request_digest=context.request_digest,
            activation_attempt_id=attempt_id,
            input_digest=input_digest,
        )
        preparation_selected = context.exact(
            "policy_activation_preparations",
            {"preparation_digest": preparation_digest},
        )
        if preparation_selected.get("present") is True:
            preparation = _row(preparation_selected)
            if (
                preparation.get("activation_attempt_id") != attempt_id
                or preparation.get("preparation_input_digest")
                    != input_digest
            ):
                raise core.TransitionKernelError(
                    "activation preparation replay diverged"
                )
            evidence_binding = _row(
                context.exact(
                    "policy_authority_activation_evidence_bindings",
                    {"preparation_digest": preparation_digest},
                )
            )
            if (
                evidence_binding.get("activation_attempt_id")
                    != attempt_id
                or evidence_binding.get("evidence_digest")
                    != decision_gate_evidence_digest
                or evidence_binding.get("consumed_operation_id")
                    != operation_id
                or evidence_binding.get("status") != "prepared"
            ):
                raise core.TransitionKernelError(
                    "activation evidence binding replay diverged"
                )
            _consumed_decision_gate_statement(
                context,
                evidence_digest=decision_gate_evidence_digest,
                consumed_operation_id=operation_id,
            )
            signature_selected = context.exact(
                "policy_authority_external_evidence_receipts",
                {"evidence_digest": policy_signature_evidence_digest},
            )
            signature_row = _row(signature_selected)
            _validated_input_evidence(
                context,
                evidence_digest=policy_signature_evidence_digest,
                input_digest=input_digest,
                subject_digest=activation["candidate_policy_hash"],
            )
            context.consumed_evidence(
                evidence_type="policy-signature-verification/v1",
                evidence_digest=policy_signature_evidence_digest,
                binding_digest=core.require_digest(
                    signature_row.get("binding_digest"),
                    "policy signature binding",
                ),
                consumed_operation_id=operation_id,
            )
            submissions = []
            for ordinal in range(1, 8):
                prepared = _row(
                    context.exact(
                        "policy_activation_prepared_transitions",
                        {
                            "preparation_digest": preparation_digest,
                            "transition_ordinal": ordinal,
                        },
                    )
                )
                submissions.append(prepared)
            return core.KernelTransition(
                mutations=(),
                result={
                    "ok": True,
                    "idempotent": True,
                    "activation_attempt_id": attempt_id,
                    "preparation_digest": preparation_digest,
                    "preparation_input_digest": input_digest,
                    "transition_manifest_root_digest":
                        preparation[
                            "transition_manifest_root_digest"
                        ],
                    "audit_submissions": submissions,
                },
                work_units=16,
            )
        if (
            context.exact(
                "policy_activation_attempts",
                {"activation_attempt_id": attempt_id},
            ).get("present") is True
            or context.exact(
                "policy_activation_finalizations",
                {"preparation_digest": preparation_digest},
            ).get("present") is True
            or context.exact(
                "policy_activation_aborts",
                {"preparation_digest": preparation_digest},
            ).get("present") is True
        ):
            raise core.TransitionKernelError(
                "activation preparation identity is already occupied"
            )
        now_epoch_ns = _database_epoch_ns(context.database_now)
        if not (
            int(activation["created_at_epoch_ns"])
            <= now_epoch_ns
            < int(activation["expires_at_epoch_ns"])
        ):
            raise core.TransitionKernelError(
                "activation preparation is outside its validity interval"
            )
        generation = _row(
            context.exact(
                "policy_shadow_generation_publications",
                {
                    "generation_publication_envelope_digest":
                        generation_envelope_digest
                },
            )
        )
        artifact = _row(
            context.exact(
                "policy_candidate_artifacts",
                {
                    "artifact_envelope_digest":
                        activation["artifact_envelope_digest"]
                },
            )
        )
        if (
            artifact.get("artifact_payload_digest")
                != activation["artifact_payload_digest"]
            or artifact.get("policy_hash")
                != activation["candidate_policy_hash"]
            or artifact.get("policy_sequence")
                != activation["candidate_policy_sequence"]
            or artifact.get("rollback_epoch")
                != activation["candidate_rollback_epoch"]
        ):
            raise core.TransitionKernelError(
                "activation candidate artifact diverged"
            )
        decision_statement, binding, binding_digest = (
            _decision_gate_statement(
                context,
                decision_gate_evidence_digest,
            )
        )
        _validate_generation_binding(generation, binding, activation)
        _validate_activation_publication_projection(
            receipt=publication_receipt,
            activation=activation,
            activation_revisions=activation_revisions,
            canary_revisions=canary_revisions,
            decision_statement=decision_statement,
            binding=binding,
        )
        if (
            binding["policyHighWaterAfterDigest"]
                == binding["policyHighWaterBeforeDigest"]
            or binding["activationPublicationReceiptDigest"]
                != decision_statement[
                    "activationPublicationEnvelope"
                ]["signedReceiptSha256"]
        ):
            raise core.TransitionKernelError(
                "activation publication evidence is not a transition"
            )
        current_high_water = _row(
            context.exact(
                "policy_high_water",
                {"scope": "active"},
            )
        )
        high_water_material = {
            "policyHash": current_high_water.get("policy_hash"),
            "policyId": current_high_water.get("policy_id"),
            "rollbackEpoch": current_high_water.get("rollback_epoch"),
            "scope": "active",
            "sequence": current_high_water.get("sequence"),
        }
        if (
            _sha256(core.canonical_bytes(high_water_material))
                != activation["expected_high_water_digest"]
            or current_high_water.get("policy_hash")
                != activation["predecessor_policy_hash"]
            or current_high_water.get("sequence")
                != activation["expected_active_policy_sequence"]
            or current_high_water.get("rollback_epoch")
                != activation["expected_active_rollback_epoch"]
        ):
            raise core.TransitionKernelError(
                "activation high-water predecessor changed"
            )
        approval_row = _row(
            context.exact(
                "policy_activation_approvals",
                {"approval_id": activation["approval_id"]},
            )
        )
        if approval_row != approval:
            raise core.TransitionKernelError(
                "activation approval snapshot diverged"
            )
        for index, member in enumerate(members, start=1):
            if _row(
                context.exact(
                    "policy_activation_approval_members",
                    {
                        "approval_id": activation["approval_id"],
                        "member_ordinal": index,
                    },
                )
            ) != member:
                raise core.TransitionKernelError(
                    "activation approval member snapshot diverged"
                )
        _validated_input_evidence(
            context,
            evidence_digest=policy_signature_evidence_digest,
            input_digest=input_digest,
            subject_digest=activation["candidate_policy_hash"],
        )
        stages = _activation_stages(
            activation=activation,
            activation_revisions=activation_revisions,
            canary_revisions=canary_revisions,
            decision_gate_evidence_digest=
                decision_gate_evidence_digest,
            created_at=_database_iso(context.database_now),
        )
        manifest = [
            {
                "ordinal": ordinal,
                "purpose": stage["purpose"],
                "transitionDigest":
                    stage["transition"]["transition_digest"],
                "outboxId": stage["outbox"]["id"],
                "outboxEventDigest":
                    stage["outbox"]["event_digest"],
                "eventPayloadDigest":
                    stage["transition"]["event_payload_digest"],
                "eventType":
                    stage["transition"]["event_type"],
                "entityKind":
                    stage["transition"]["entity_kind"],
                "entityId":
                    stage["transition"]["entity_id"],
                "entityRevision":
                    stage["transition"]["entity_revision"],
                "stateDigest":
                    stage["transition"]["state_digest"],
                "previousStateDigest":
                    stage["transition"]["previous_state_digest"],
            }
            for ordinal, stage in enumerate(stages, start=1)
        ]
        manifest_json = core.canonical_bytes(manifest).decode("ascii")
        manifest_digest = core.framed_digest(
            "catchplate.policyActivationTransitionManifest/v2",
            manifest_json.encode("ascii"),
        )
        authority_snapshot = {
            "schema":
                "catchplate.policyActivationAuthoritySnapshot/v2",
            "approval": approval,
            "approvalMembers": members,
            "generationPublicationEnvelopeDigest":
                generation_envelope_digest,
            "generationId": generation["generation_id_digest"],
            "policyHighWater": current_high_water,
            "decisionGateEvidenceDigest":
                decision_gate_evidence_digest,
            "decisionGateEvidenceChainDigest":
                decision_statement["evidenceChainDigest"],
        }
        authority_snapshot_json = core.canonical_bytes(
            authority_snapshot
        ).decode("ascii")
        authority_snapshot_digest = core.framed_digest(
            "catchplate.policyActivationAuthoritySnapshot/v2",
            authority_snapshot_json.encode("ascii"),
        )
        preparation_input_json = core.canonical_bytes(
            input_material
        ).decode("ascii")
        prepared_canary_revision = core.require_integer(
            canary_revisions[0]["previous_revision"],
            "prepared canary revision",
            minimum=1,
            maximum=_SIGNED_BIGINT_MAX,
        )
        prepared_canary_state_digest = core.require_digest(
            canary_revisions[0]["previous_state_digest"],
            "prepared canary state",
        )
        preparation = {
            "preparation_digest": preparation_digest,
            "activation_attempt_id": attempt_id,
            "activation_intent_digest":
                activation["activation_intent_digest"],
            "publication_intent_digest":
                activation["publication_intent_digest"],
            "readiness_payload_digest":
                activation["readiness_payload_digest"],
            "approval_id": activation["approval_id"],
            "approval_consumption_digest":
                consumption["consumption_digest"],
            "rollback_authorization_digest":
                activation["rollback_authorization_digest"],
            "expected_high_water_digest":
                activation["expected_high_water_digest"],
            "predecessor_policy_hash":
                activation["predecessor_policy_hash"],
            "candidate_policy_hash":
                activation["candidate_policy_hash"],
            "candidate_policy_sequence":
                activation["candidate_policy_sequence"],
            "candidate_rollback_epoch":
                activation["candidate_rollback_epoch"],
            "prepared_canary_revision": prepared_canary_revision,
            "prepared_canary_state_digest":
                prepared_canary_state_digest,
            "authority_snapshot_json": authority_snapshot_json,
            "authority_snapshot_digest": authority_snapshot_digest,
            "preparation_input_json": preparation_input_json,
            "preparation_input_digest": input_digest,
            "transition_manifest_json": manifest_json,
            "transition_manifest_root_digest": manifest_digest,
            "transition_count": 7,
            "prepared_at_epoch_ns": now_epoch_ns,
            "expires_at_epoch_ns": activation["expires_at_epoch_ns"],
        }
        evidence_binding_row = {
            "preparation_digest": preparation_digest,
            "activation_attempt_id": attempt_id,
            "evidence_digest": decision_gate_evidence_digest,
            "binding_digest": binding_digest,
            "evidence_chain_digest":
                decision_statement["evidenceChainDigest"],
            "generation_publication_envelope_digest":
                decision_statement[
                    "generationPublicationEnvelopeDigest"
                ],
            "activation_publication_envelope_digest":
                decision_statement[
                    "activationPublicationEnvelopeDigest"
                ],
            "runtime_verifier_envelope_digest":
                decision_statement[
                    "runtimeAttestationVerifierEnvelopeDigest"
                ],
            "generation_id_digest": binding["generationId"],
            "publication_request_id":
                binding["publicationRequestId"],
            "replay_id": binding["replayId"],
            "publication_revision": binding["publicationRevision"],
            "consumed_operation_id": operation_id,
            "status": "prepared",
            "created_at_epoch_ns": now_epoch_ns,
            "finalized_at_epoch_ns": None,
            "source_revision": authority_contract.SOURCE_REVISION,
        }
        mutations: list[dict[str, Any]] = [
            context.consume_decision_gate_publication_evidence(
                evidence_digest=decision_gate_evidence_digest,
                expected_binding=binding,
                operation_id=operation_id,
            ),
            context.consume_evidence(
                evidence_type="policy-signature-verification/v1",
                evidence_digest=policy_signature_evidence_digest,
                binding_digest=_row(
                    context.exact(
                        "policy_authority_external_evidence_receipts",
                        {
                            "evidence_digest":
                                policy_signature_evidence_digest
                        },
                    )
                )["binding_digest"],
                operation_id=operation_id,
            ),
            *_fresh_audit_mutations(
                context,
                operation_id=operation_id,
                outbox_rows=tuple(stage["outbox"] for stage in stages),
            ),
        ]
        attempt_mutation = _immutable_mutation(
            context,
            table="policy_activation_attempts",
            key={"activation_attempt_id": attempt_id},
            row=activation,
        )
        if attempt_mutation is not None:
            mutations.append(attempt_mutation)
        prepared_mutations: list[dict[str, Any]] = []
        for ordinal, stage in enumerate(stages, start=1):
            transition_mutation = _immutable_mutation(
                context,
                table="policy_authority_transition_audits",
                key={
                    "transition_digest":
                        stage["transition"]["transition_digest"]
                },
                row=stage["transition"],
            )
            prepared_transition = {
                "preparation_digest": preparation_digest,
                "transition_ordinal": ordinal,
                "transition_purpose": stage["purpose"],
                "transition_digest":
                    stage["transition"]["transition_digest"],
                "outbox_id": stage["outbox"]["id"],
                "outbox_event_digest":
                    stage["outbox"]["event_digest"],
                "event_payload_digest":
                    stage["transition"]["event_payload_digest"],
                "event_type": stage["transition"]["event_type"],
                "entity_kind": stage["transition"]["entity_kind"],
                "entity_id": stage["transition"]["entity_id"],
                "entity_revision":
                    stage["transition"]["entity_revision"],
                "state_digest": stage["transition"]["state_digest"],
                "previous_state_digest":
                    stage["transition"]["previous_state_digest"],
            }
            prepared_mutation = _immutable_mutation(
                context,
                table="policy_activation_prepared_transitions",
                key={
                    "preparation_digest": preparation_digest,
                    "transition_ordinal": ordinal,
                },
                row=prepared_transition,
            )
            if transition_mutation is not None:
                mutations.append(transition_mutation)
            if prepared_mutation is not None:
                prepared_mutations.append(prepared_mutation)
        preparation_mutation = _immutable_mutation(
            context,
            table="policy_activation_preparations",
            key={"preparation_digest": preparation_digest},
            row=preparation,
        )
        if preparation_mutation is not None:
            mutations.append(preparation_mutation)
        evidence_binding_mutation = _immutable_mutation(
            context,
            table="policy_authority_activation_evidence_bindings",
            key={"preparation_digest": preparation_digest},
            row=evidence_binding_row,
        )
        if evidence_binding_mutation is not None:
            mutations.append(evidence_binding_mutation)
        mutations.extend(prepared_mutations)
        return core.KernelTransition(
            mutations=tuple(mutations),
            result={
                "ok": True,
                "idempotent": False,
                "activation_attempt_id": attempt_id,
                "preparation_digest": preparation_digest,
                "preparation_input_digest": input_digest,
                "transition_manifest_root_digest": manifest_digest,
                "audit_submissions": [
                    {
                        "transition_purpose": stage["purpose"],
                        **stage["transition"],
                    }
                    for stage in stages
                ],
            },
            work_units=96,
        )


def _activation_inclusion_arguments(
    arguments: Mapping[str, Any],
) -> tuple[str, list[dict[str, str]], str, str, str]:
    core.require_exact_arguments(
        arguments,
        _ACTIVATION_RECORD_INCLUSION_FIELDS,
    )
    preparation_digest = core.require_digest(
        arguments["preparationDigest"],
        "activation preparation",
    )
    raw_inclusions = _list(
        arguments["inclusions"],
        "activation audit inclusions",
        maximum=7,
    )
    if not raw_inclusions:
        raise core.TransitionKernelError(
            "activation inclusion page is empty"
        )
    inclusions: list[dict[str, str]] = []
    for item in raw_inclusions:
        value = _mapping(
            item,
            "activation inclusion identity",
            fields=frozenset(
                {
                    "evidenceDigest",
                    "inclusionReceiptEnvelopeDigest",
                }
            ),
        )
        inclusions.append(
            {
                "evidenceDigest": core.require_digest(
                    value["evidenceDigest"],
                    "audit inclusion evidence",
                ),
                "inclusionReceiptEnvelopeDigest":
                    core.require_digest(
                        value["inclusionReceiptEnvelopeDigest"],
                        "audit inclusion envelope",
                    ),
            }
        )
    if (
        len(
            {
                item["evidenceDigest"]
                for item in inclusions
            }
        ) != len(inclusions)
        or len(
            {
                item["inclusionReceiptEnvelopeDigest"]
                for item in inclusions
            }
        ) != len(inclusions)
    ):
        raise core.TransitionKernelError(
            "activation inclusion identities are duplicated"
        )
    audit_store_identity_digest = core.require_digest(
        arguments["auditStoreIdentityDigest"],
        "audit store identity",
    )
    generation_envelope_digest = core.require_digest(
        arguments["generationPublicationEnvelopeDigest"],
        "activation generation publication",
    )
    decision_gate_evidence_digest = core.require_digest(
        arguments["decisionGateEvidenceDigest"],
        "activation decision-gate evidence",
    )
    return (
        preparation_digest,
        inclusions,
        audit_store_identity_digest,
        generation_envelope_digest,
        decision_gate_evidence_digest,
    )


def _inclusion_statement(
    context: core.KernelContext,
    *,
    evidence_digest: str,
    preparation_digest: str,
    envelope_digest: str,
    consumed_operation_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    _, statement, binding_digest = _external_statement(
        context,
        evidence_type="audit-inclusion/v1",
        evidence_digest=evidence_digest,
        binding_domain=(
            "catchplate.policyAuthorityAuditInclusionBinding/v1"
        ),
        consumed_operation_id=consumed_operation_id,
    )
    if (
        set(statement)
        != {
            "schema",
            "operation",
            "preparationDigest",
            "receipt",
        }
        or statement.get("schema")
            != "catchplate.policyAuthorityVerifiedAuditInclusion/v1"
        or statement.get("operation") != context.operation
        or statement.get("preparationDigest") != preparation_digest
        or not isinstance(statement.get("receipt"), Mapping)
    ):
        raise core.TransitionKernelError(
            "audit inclusion evidence statement diverged"
        )
    receipt = dict(statement["receipt"])
    if (
        receipt.get("inclusion_receipt_envelope_digest")
            != envelope_digest
        or receipt.get("external_evidence_digest")
            not in {None, evidence_digest}
    ):
        raise core.TransitionKernelError(
            "audit inclusion receipt identity diverged"
        )
    return statement, receipt, binding_digest


@dataclass(frozen=True, slots=True)
class _PolicyActivationRecordInclusionKernel:
    operation: str = "policy.activation.record-inclusion"
    handler: str = "catchplate_policy_authority_record_inclusion"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "policy.activation.record-inclusion",
        "catchplate_policy_authority_record_inclusion",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        core.require_digest(
            request_digest,
            "activation inclusion request digest",
        )
        (
            preparation_digest,
            inclusions,
            audit_store_identity_digest,
            generation_envelope_digest,
            decision_gate_evidence_digest,
        ) = _activation_inclusion_arguments(arguments)
        queries: list[core.BoundedQuery] = [
            _exact_query(
                operation=self.operation,
                name="preparation",
                table="policy_activation_preparations",
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="activation_evidence_binding",
                table=(
                    "policy_authority_activation_evidence_bindings"
                ),
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="abort",
                table="policy_activation_aborts",
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="decision_evidence",
                table="policy_authority_external_evidence_receipts",
                key={"evidence_digest": decision_gate_evidence_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="generation_publication",
                table="policy_shadow_generation_publications",
                key={
                    "generation_publication_envelope_digest":
                        generation_envelope_digest
                },
            ),
            _exact_query(
                operation=self.operation,
                name="inclusion_head",
                table="policy_authority_audit_inclusion_heads",
                key={
                    "audit_store_identity_digest":
                        audit_store_identity_digest
                },
            ),
        ]
        for ordinal in range(1, 8):
            queries.append(
                _exact_query(
                    operation=self.operation,
                    name=f"prepared_transition_{ordinal}",
                    table="policy_activation_prepared_transitions",
                    key={
                        "preparation_digest": preparation_digest,
                        "transition_ordinal": ordinal,
                    },
                )
            )
        for index, inclusion in enumerate(inclusions, start=1):
            queries.extend(
                (
                    _exact_query(
                        operation=self.operation,
                        name=f"inclusion_evidence_{index}",
                        table=(
                            "policy_authority_"
                            "external_evidence_receipts"
                        ),
                        key={
                            "evidence_digest":
                                inclusion["evidenceDigest"]
                        },
                    ),
                    _exact_query(
                        operation=self.operation,
                        name=f"inclusion_receipt_{index}",
                        table=(
                            "policy_authority_"
                            "audit_inclusion_receipts"
                        ),
                        key={
                            "inclusion_receipt_envelope_digest":
                                inclusion[
                                    "inclusionReceiptEnvelopeDigest"
                                ]
                        },
                    ),
                )
            )
        return tuple(queries)

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        (
            preparation_digest,
            inclusions,
            audit_store_identity_digest,
            generation_envelope_digest,
            decision_gate_evidence_digest,
        ) = _activation_inclusion_arguments(context.arguments)
        preparation = _row(
            context.exact(
                "policy_activation_preparations",
                {"preparation_digest": preparation_digest},
            )
        )
        evidence_binding_row = _row(
            context.exact(
                "policy_authority_activation_evidence_bindings",
                {"preparation_digest": preparation_digest},
            )
        )
        if (
            evidence_binding_row.get("evidence_digest")
                != decision_gate_evidence_digest
            or evidence_binding_row.get(
                "generation_publication_envelope_digest"
            )
                != generation_envelope_digest
            or evidence_binding_row.get("status") != "prepared"
            or evidence_binding_row.get("activation_attempt_id")
                != preparation.get("activation_attempt_id")
            or context.exact(
                "policy_activation_aborts",
                {"preparation_digest": preparation_digest},
            ).get("present") is True
        ):
            raise core.TransitionKernelError(
                "activation inclusion preparation is not authoritative"
            )
        _row(
            context.exact(
                "policy_shadow_generation_publications",
                {
                    "generation_publication_envelope_digest":
                        generation_envelope_digest
                },
            )
        )
        _consumed_decision_gate_statement(
            context,
            evidence_digest=decision_gate_evidence_digest,
            consumed_operation_id=core.require_text(
                evidence_binding_row["consumed_operation_id"],
                "decision-gate consuming operation",
                maximum_bytes=256,
            ),
        )
        prepared_by_transition: dict[str, dict[str, Any]] = {}
        for ordinal in range(1, 8):
            prepared = _row(
                context.exact(
                    "policy_activation_prepared_transitions",
                    {
                        "preparation_digest": preparation_digest,
                        "transition_ordinal": ordinal,
                    },
                )
            )
            prepared_by_transition[
                core.require_digest(
                    prepared["transition_digest"],
                    "prepared transition",
                )
            ] = prepared
        operation_id = _operation_id(
            self.operation,
            context.request_digest,
        )
        selected_receipts = [
            context.exact(
                "policy_authority_audit_inclusion_receipts",
                {
                    "inclusion_receipt_envelope_digest":
                        inclusion[
                            "inclusionReceiptEnvelopeDigest"
                        ]
                },
            )
            for inclusion in inclusions
        ]
        selected_by_envelope = {
            str(selected["key"][
                "inclusion_receipt_envelope_digest"
            ]): selected
            for selected in selected_receipts
        }
        existing_count = sum(
            selected.get("present") is True
            for selected in selected_receipts
        )
        if existing_count not in {0, len(selected_receipts)}:
            raise core.TransitionKernelError(
                "partial activation inclusion replay is not identical"
            )
        replay = existing_count == len(selected_receipts)
        receipts: list[
            tuple[dict[str, Any], str, str]
        ] = []
        for inclusion in inclusions:
            _, receipt, binding_digest = _inclusion_statement(
                context,
                evidence_digest=inclusion["evidenceDigest"],
                preparation_digest=preparation_digest,
                envelope_digest=(
                    inclusion["inclusionReceiptEnvelopeDigest"]
                ),
                consumed_operation_id=operation_id if replay else None,
            )
            transition_digest = core.require_digest(
                receipt.get("transition_digest"),
                "included transition",
            )
            prepared = prepared_by_transition.get(transition_digest)
            if (
                prepared is None
                or receipt.get("outbox_id")
                    != prepared.get("outbox_id")
                or receipt.get("outbox_event_digest")
                    != prepared.get("outbox_event_digest")
                or receipt.get("audit_store_identity_digest")
                    != audit_store_identity_digest
                or receipt.get("audit_ledger_namespace")
                    != "catchplate.policy-authority"
                or receipt.get("signing_key_id")
                    != receipt.get(
                        "audit_signer_public_key_digest"
                    )
            ):
                raise core.TransitionKernelError(
                    "audit inclusion does not bind a prepared transition"
                )
            receipts.append(
                (
                    receipt,
                    inclusion["evidenceDigest"],
                    binding_digest,
                )
            )
        receipts.sort(
            key=lambda item: core.require_integer(
                item[0].get("audit_sequence"),
                "audit inclusion sequence",
                minimum=1,
                maximum=_SIGNED_BIGINT_MAX,
            )
        )
        sequences = [
            int(item[0]["audit_sequence"]) for item in receipts
        ]
        head_selected = context.exact(
            "policy_authority_audit_inclusion_heads",
            {
                "audit_store_identity_digest":
                    audit_store_identity_digest
            },
        )
        previous_sequence = 0
        previous_hash: str | None = None
        if head_selected.get("present") is True:
            head = _row(head_selected)
            previous_sequence = core.require_integer(
                head.get("audit_sequence"),
                "audit inclusion high-water",
                minimum=1,
                maximum=_SIGNED_BIGINT_MAX,
            )
            previous_hash = core.require_digest(
                head.get("audit_event_hash"),
                "audit inclusion high-water hash",
            )
        if replay:
            if (
                sequences
                    != list(
                        range(
                            sequences[0],
                            sequences[0] + len(sequences),
                        )
                    )
                or head_selected.get("present") is not True
            ):
                raise core.TransitionKernelError(
                    "activation inclusion replay lost its exact head"
                )
            for receipt, _, _ in receipts:
                selected = selected_by_envelope[
                    receipt["inclusion_receipt_envelope_digest"]
                ]
                if _row(selected) != receipt:
                    raise core.TransitionKernelError(
                        "audit inclusion replay diverged"
                    )
            last = receipts[-1][0]
            head = _row(head_selected)
            if (
                head.get("audit_sequence")
                    != last.get("audit_sequence")
                or head.get("audit_event_hash")
                    != last.get("audit_event_hash")
                or head.get("inclusion_root_digest")
                    != last.get("inclusion_root_digest")
                or head.get("inclusion_receipt_envelope_digest")
                    != last.get(
                        "inclusion_receipt_envelope_digest"
                    )
            ):
                raise core.TransitionKernelError(
                    "activation inclusion replay head diverged"
                )
            replay_identities = [
                {
                    "auditEventHash": receipt["audit_event_hash"],
                    "auditSequence": receipt["audit_sequence"],
                    "inclusionReceiptEnvelopeDigest":
                        receipt[
                            "inclusion_receipt_envelope_digest"
                        ],
                    "inclusionRootDigest":
                        receipt["inclusion_root_digest"],
                    "transitionDigest":
                        receipt["transition_digest"],
                }
                for receipt, _, _ in receipts
            ]
            replay_identity_json = core.canonical_bytes(
                replay_identities
            ).decode("ascii")
            return core.KernelTransition(
                mutations=(),
                result={
                    "ok": True,
                    "idempotent": True,
                    "preparation_digest": preparation_digest,
                    "recorded_count": len(receipts),
                    "recorded_inclusion_receipts": [
                        receipt for receipt, _, _ in receipts
                    ],
                    "inclusion_identity_set_json":
                        replay_identity_json,
                    "inclusion_identity_set_digest":
                        core.framed_digest(
                            (
                                "catchplate."
                                "policyActivationAuditInclusionSet/v2"
                            ),
                            replay_identity_json.encode("ascii"),
                        ),
                    "included_transitions": replay_identities,
                },
                work_units=24 + len(receipts) * 4,
            )
        if sequences != list(
            range(previous_sequence + 1, previous_sequence + 1 + len(receipts))
        ):
            raise core.TransitionKernelError(
                "audit inclusion sequence is not contiguous"
            )
        for receipt, _, _ in receipts:
            supplied_previous = receipt.get(
                "previous_audit_event_hash"
            )
            if supplied_previous != previous_hash:
                raise core.TransitionKernelError(
                    "audit inclusion predecessor changed"
                )
            previous_hash = core.require_digest(
                receipt.get("audit_event_hash"),
                "audit inclusion event hash",
            )
        mutations: list[dict[str, Any]] = []
        recorded: list[dict[str, Any]] = []
        for receipt, evidence_digest, binding_digest in receipts:
            selected = context.exact(
                "policy_authority_audit_inclusion_receipts",
                {
                    "inclusion_receipt_envelope_digest":
                        receipt[
                            "inclusion_receipt_envelope_digest"
                        ]
                },
            )
            if selected.get("present") is True:
                if _row(selected) != receipt:
                    raise core.TransitionKernelError(
                        "audit inclusion replay diverged"
                    )
                context.consumed_evidence(
                    evidence_type="audit-inclusion/v1",
                    evidence_digest=evidence_digest,
                    binding_digest=binding_digest,
                    consumed_operation_id=operation_id,
                )
            else:
                mutations.extend(
                    (
                        context.consume_evidence(
                            evidence_type="audit-inclusion/v1",
                            evidence_digest=evidence_digest,
                            binding_digest=binding_digest,
                            operation_id=operation_id,
                        ),
                        core.mutation(
                            operation=self.operation,
                            selected=selected,
                            row=receipt,
                        ),
                    )
                )
            recorded.append(receipt)
        last = receipts[-1][0]
        next_head = {
            "audit_store_identity_digest":
                audit_store_identity_digest,
            "audit_ledger_namespace":
                "catchplate.policy-authority",
            "audit_signer_public_key_digest":
                last["audit_signer_public_key_digest"],
            "signing_key_id": last["signing_key_id"],
            "audit_sequence": last["audit_sequence"],
            "audit_event_hash": last["audit_event_hash"],
            "inclusion_root_digest":
                last["inclusion_root_digest"],
            "inclusion_receipt_envelope_digest":
                last["inclusion_receipt_envelope_digest"],
            "updated_at_epoch_ns":
                _database_epoch_ns(context.database_now),
        }
        if head_selected.get("present") is True:
            if (
                _row(head_selected).get("audit_sequence")
                    == next_head["audit_sequence"]
                and _row(head_selected).get(
                    "inclusion_receipt_envelope_digest"
                )
                    == next_head[
                        "inclusion_receipt_envelope_digest"
                    ]
            ):
                pass
            else:
                mutations.append(
                    core.mutation(
                        operation=self.operation,
                        selected=head_selected,
                        row=next_head,
                    )
                )
        else:
            mutations.append(
                core.mutation(
                    operation=self.operation,
                    selected=head_selected,
                    row=next_head,
                )
            )
        inclusion_identities = [
            {
                "auditEventHash": receipt["audit_event_hash"],
                "auditSequence": receipt["audit_sequence"],
                "inclusionReceiptEnvelopeDigest":
                    receipt[
                        "inclusion_receipt_envelope_digest"
                    ],
                "inclusionRootDigest":
                    receipt["inclusion_root_digest"],
                "transitionDigest":
                    receipt["transition_digest"],
            }
            for receipt in recorded
        ]
        identity_set_json = core.canonical_bytes(
            inclusion_identities
        ).decode("ascii")
        identity_set_digest = core.framed_digest(
            "catchplate.policyActivationAuditInclusionSet/v2",
            identity_set_json.encode("ascii"),
        )
        return core.KernelTransition(
            mutations=tuple(mutations),
            result={
                "ok": True,
                "preparation_digest": preparation_digest,
                "recorded_count": len(recorded),
                "recorded_inclusion_receipts": recorded,
                "inclusion_identity_set_json": identity_set_json,
                "inclusion_identity_set_digest":
                    identity_set_digest,
                "included_transitions": inclusion_identities,
            },
            work_units=32 + len(recorded) * 8,
        )


def _activation_finalize_arguments(
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    core.require_exact_arguments(arguments, _ACTIVATION_FINALIZE_FIELDS)
    inclusion_digests = [
        core.require_digest(value, "activation inclusion identity")
        for value in _list(
            arguments["inclusionReceiptEnvelopeDigests"],
            "activation inclusion identities",
            maximum=7,
        )
    ]
    activation_revisions = [
        core.require_integer(
            value,
            "activation revision address",
            minimum=1,
            maximum=_SIGNED_BIGINT_MAX,
        )
        for value in _list(
            arguments["activationRevisionNumbers"],
            "activation revision addresses",
            maximum=4,
        )
    ]
    canary_revisions = [
        core.require_integer(
            value,
            "canary revision address",
            minimum=1,
            maximum=_SIGNED_BIGINT_MAX,
        )
        for value in _list(
            arguments["canaryRevisionNumbers"],
            "canary revision addresses",
            maximum=2,
        )
    ]
    approval_ids = [
        core.require_text(
            value,
            "control-plane approval address",
            maximum_bytes=256,
        )
        for value in _list(
            arguments["controlPlaneApprovalIds"],
            "control-plane approval addresses",
            maximum=2,
        )
    ]
    approver_ids = [
        core.require_text(
            value,
            "activation approver address",
            maximum_bytes=1024,
        )
        for value in _list(
            arguments["approverIds"],
            "activation approver addresses",
            maximum=2,
        )
    ]
    if (
        len(inclusion_digests) != 7
        or len(set(inclusion_digests)) != 7
        or len(activation_revisions) != 4
        or len(set(activation_revisions)) != 4
        or len(canary_revisions) != 2
        or len(set(canary_revisions)) != 2
        or not approval_ids
        or len(approval_ids) != len(set(approval_ids))
        or len(approval_ids) != len(approver_ids)
        or len(approver_ids) != len(set(approver_ids))
    ):
        raise core.TransitionKernelError(
            "activation finalization addresses are not exact"
        )
    rollback_digest = arguments["rollbackAuthorizationDigest"]
    if rollback_digest is not None:
        rollback_digest = core.require_digest(
            rollback_digest,
            "activation rollback authorization",
        )
    return {
        "preparation_digest": core.require_digest(
            arguments["preparationDigest"],
            "activation finalization preparation",
        ),
        "inclusion_digests": inclusion_digests,
        "activation_attempt_id": core.require_text(
            arguments["activationAttemptId"],
            "activation finalization attempt",
            maximum_bytes=256,
        ),
        "canary_id": core.require_text(
            arguments["canaryId"],
            "activation finalization canary",
            maximum_bytes=256,
        ),
        "activation_revisions": activation_revisions,
        "canary_revisions": canary_revisions,
        "control_plane_approval_ids": approval_ids,
        "approver_ids": approver_ids,
        "requester_id": core.require_text(
            arguments["requesterId"],
            "activation finalization requester",
            maximum_bytes=1024,
        ),
        "publication_receipt_envelope_digest":
            core.require_digest(
                arguments["publicationReceiptEnvelopeDigest"],
                "activation publication receipt",
            ),
        "rollback_authorization_digest": rollback_digest,
    }


def _stored_activation_preparation_input(
    preparation: Mapping[str, Any],
) -> dict[str, Any]:
    value = _mapping_json(
        preparation.get("preparation_input_json"),
        "stored activation preparation input",
    )
    if (
        set(value) != _ACTIVATION_PREPARATION_INPUT_FIELDS
        or value.get("schema")
            != "catchplate.policyActivationPreparationInput/v2"
        or core.framed_digest(
            "catchplate.policyActivationPreparationInput/v2",
            core.canonical_bytes(value),
        )
            != preparation.get("preparation_input_digest")
    ):
        raise core.TransitionKernelError(
            "stored activation preparation input changed"
        )
    return value


def _stored_revision(
    revision: Mapping[str, Any],
    prepared: Mapping[str, Any],
    *,
    entity_kind: str,
) -> dict[str, Any]:
    value = dict(revision)
    event_type = value.pop("event_type")
    value.pop("actor_id")
    if (
        prepared.get("entity_kind") != entity_kind
        or prepared.get("entity_id")
            != (
                value["activation_attempt_id"]
                if entity_kind == "activation"
                else value["canary_id"]
            )
        or prepared.get("entity_revision") != value["revision"]
        or prepared.get("state_digest") != value["state_digest"]
        or prepared.get("previous_state_digest")
            != value["previous_state_digest"]
        or prepared.get("event_type") != event_type
    ):
        raise core.TransitionKernelError(
            "prepared revision transition diverged"
        )
    return {
        **value,
        "transition_digest": prepared["transition_digest"],
        "transition_entity_kind": entity_kind,
        "transition_event_type": event_type,
    }


def _active_rbac_binding(
    context: core.KernelContext,
    subject_id: str,
) -> dict[str, Any]:
    row = _row(
        context.exact(
            "rbac_role_bindings",
            {"subject_id": subject_id},
        )
    )
    roles = _list(
        json.loads(str(row.get("roles_json"))),
        "RBAC roles",
        maximum=64,
    )
    if (
        row.get("status") != "active"
        or "policy_publisher" not in roles
        or any(not isinstance(role, str) for role in roles)
    ):
        raise core.TransitionKernelError(
            "activation RBAC authority is not current"
        )
    return row


@dataclass(frozen=True, slots=True)
class _PolicyActivationFinalizeKernel:
    operation: str = "policy.activation.finalize"
    handler: str = "catchplate_policy_authority_finalize"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "policy.activation.finalize",
        "catchplate_policy_authority_finalize",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        core.require_digest(
            request_digest,
            "activation finalization request digest",
        )
        values = _activation_finalize_arguments(arguments)
        preparation_digest = values["preparation_digest"]
        preparation_reference = core.SelectedRowFieldReference(
            table="policy_activation_preparations",
            key={"preparation_digest": preparation_digest},
            column="approval_id",
        )
        candidate_reference = core.SelectedRowFieldReference(
            table="policy_activation_preparations",
            key={"preparation_digest": preparation_digest},
            column="candidate_policy_hash",
        )
        sidecar_evidence_reference = core.SelectedRowFieldReference(
            table="policy_authority_activation_evidence_bindings",
            key={"preparation_digest": preparation_digest},
            column="evidence_digest",
        )
        sidecar_generation_reference = core.SelectedRowFieldReference(
            table="policy_authority_activation_evidence_bindings",
            key={"preparation_digest": preparation_digest},
            column="generation_publication_envelope_digest",
        )
        queries: list[core.BoundedQuery] = [
            _exact_query(
                operation=self.operation,
                name="preparation",
                table="policy_activation_preparations",
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="activation_evidence_binding",
                table="policy_authority_activation_evidence_bindings",
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="decision_evidence",
                table="policy_authority_external_evidence_receipts",
                key={"evidence_digest": sidecar_evidence_reference},
            ),
            _exact_query(
                operation=self.operation,
                name="generation_publication",
                table="policy_shadow_generation_publications",
                key={
                    "generation_publication_envelope_digest":
                        sidecar_generation_reference
                },
            ),
            _exact_query(
                operation=self.operation,
                name="finalization",
                table="policy_activation_finalizations",
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="abort",
                table="policy_activation_aborts",
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="attempt",
                table="policy_activation_attempts",
                key={
                    "activation_attempt_id":
                        values["activation_attempt_id"]
                },
            ),
            _exact_query(
                operation=self.operation,
                name="approval",
                table="policy_activation_approvals",
                key={"approval_id": preparation_reference},
            ),
            _exact_query(
                operation=self.operation,
                name="approval_consumption",
                table="policy_activation_approval_consumptions",
                key={"approval_id": preparation_reference},
            ),
            _exact_query(
                operation=self.operation,
                name="active_high_water",
                table="policy_high_water",
                key={"scope": "active"},
            ),
            _exact_query(
                operation=self.operation,
                name="candidate_publication",
                table="policy_publications",
                key={"policy_hash": candidate_reference},
            ),
            _exact_query(
                operation=self.operation,
                name="publication_receipt",
                table="policy_activation_publication_receipts",
                key={
                    "publication_receipt_envelope_digest":
                        values[
                            "publication_receipt_envelope_digest"
                        ]
                },
            ),
            _exact_query(
                operation=self.operation,
                name="activation_head",
                table="policy_activation_heads",
                key={
                    "activation_attempt_id":
                        values["activation_attempt_id"]
                },
            ),
            _exact_query(
                operation=self.operation,
                name="canary_head",
                table="policy_canary_heads",
                key={"canary_id": values["canary_id"]},
            ),
            _exact_query(
                operation=self.operation,
                name="requester_rbac",
                table="rbac_role_bindings",
                key={"subject_id": values["requester_id"]},
            ),
        ]
        for ordinal in range(1, 8):
            queries.append(
                _exact_query(
                    operation=self.operation,
                    name=f"prepared_transition_{ordinal}",
                    table="policy_activation_prepared_transitions",
                    key={
                        "preparation_digest": preparation_digest,
                        "transition_ordinal": ordinal,
                    },
                )
            )
        for index, envelope_digest in enumerate(
            values["inclusion_digests"],
            start=1,
        ):
            queries.append(
                _exact_query(
                    operation=self.operation,
                    name=f"inclusion_receipt_{index}",
                    table="policy_authority_audit_inclusion_receipts",
                    key={
                        "inclusion_receipt_envelope_digest":
                            envelope_digest
                    },
                )
            )
        for index, revision in enumerate(
            values["activation_revisions"],
            start=1,
        ):
            queries.append(
                _exact_query(
                    operation=self.operation,
                    name=f"activation_revision_{index}",
                    table="policy_activation_revisions",
                    key={
                        "activation_attempt_id":
                            values["activation_attempt_id"],
                        "revision": revision,
                    },
                )
            )
        for index, revision in enumerate(
            values["canary_revisions"],
            start=1,
        ):
            queries.append(
                _exact_query(
                    operation=self.operation,
                    name=f"canary_revision_{index}",
                    table="policy_canary_revisions",
                    key={
                        "canary_id": values["canary_id"],
                        "revision": revision,
                    },
                )
            )
        for index, (
            approval_id,
            approver_id,
        ) in enumerate(
            zip(
                values["control_plane_approval_ids"],
                values["approver_ids"],
                strict=True,
            ),
            start=1,
        ):
            queries.extend(
                (
                    _exact_query(
                        operation=self.operation,
                        name=f"approval_member_{index}",
                        table="policy_activation_approval_members",
                        key={
                            "approval_id": preparation_reference,
                            "member_ordinal": index,
                        },
                    ),
                    _exact_query(
                        operation=self.operation,
                        name=f"control_approval_{index}",
                        table="control_plane_approvals",
                        key={"id": approval_id},
                    ),
                    _exact_query(
                        operation=self.operation,
                        name=f"approver_rbac_{index}",
                        table="rbac_role_bindings",
                        key={"subject_id": approver_id},
                    ),
                )
            )
        rollback_digest = values["rollback_authorization_digest"]
        if rollback_digest is not None:
            queries.extend(
                (
                    _exact_query(
                        operation=self.operation,
                        name="rollback_authority",
                        table="policy_activation_rollback_authorities",
                        key={
                            "rollback_authorization_payload_digest":
                                rollback_digest
                        },
                    ),
                    _exact_query(
                        operation=self.operation,
                        name="rollback_revocation",
                        table=(
                            "policy_activation_"
                            "rollback_authority_revocations"
                        ),
                        key={
                            "rollback_authorization_payload_digest":
                                rollback_digest
                        },
                    ),
                    _exact_query(
                        operation=self.operation,
                        name="rollback_consumption",
                        table=(
                            "policy_activation_rollback_consumptions"
                        ),
                        key={
                            "rollback_authorization_payload_digest":
                                rollback_digest
                        },
                    ),
                )
            )
        return tuple(queries)

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        values = _activation_finalize_arguments(context.arguments)
        preparation_digest = values["preparation_digest"]
        preparation = _row(
            context.exact(
                "policy_activation_preparations",
                {"preparation_digest": preparation_digest},
            )
        )
        preparation_input = _stored_activation_preparation_input(
            preparation
        )
        activation = _mapping(
            preparation_input["activation"],
            "stored activation attempt",
            fields=_ACTIVATION_ATTEMPT_FIELDS,
        )
        approval = _mapping(
            preparation_input["approval"],
            "stored activation approval",
        )
        members = [
            _mapping(item, "stored activation approval member")
            for item in _list(
                preparation_input["approvalMembers"],
                "stored activation approval members",
                maximum=2,
            )
        ]
        consumption = _mapping(
            preparation_input["approvalConsumption"],
            "stored activation approval consumption",
            fields=_ACTIVATION_CONSUMPTION_FIELDS,
        )
        activation_revisions = [
            _mapping(
                item,
                "stored activation revision",
                fields=_ACTIVATION_REVISION_FIELDS,
            )
            for item in _list(
                preparation_input["activationRevisions"],
                "stored activation revisions",
                maximum=4,
            )
        ]
        canary_revisions = [
            _mapping(
                item,
                "stored canary revision",
                fields=_CANARY_REVISION_FIELDS,
            )
            for item in _list(
                preparation_input["canaryRevisions"],
                "stored canary revisions",
                maximum=2,
            )
        ]
        publication_receipt = _mapping(
            preparation_input["publicationReceipt"],
            "stored activation publication receipt",
            fields=_ACTIVATION_PUBLICATION_RECEIPT_FIELDS,
        )
        if (
            preparation.get("activation_attempt_id")
                != values["activation_attempt_id"]
            or activation.get("activation_attempt_id")
                != values["activation_attempt_id"]
            or activation.get("canary_id") != values["canary_id"]
            or activation.get("requested_by")
                != values["requester_id"]
            or publication_receipt.get(
                "publication_receipt_envelope_digest"
            )
                != values[
                    "publication_receipt_envelope_digest"
                ]
            or activation.get("rollback_authorization_digest")
                != values["rollback_authorization_digest"]
            or [row["revision"] for row in activation_revisions]
                != values["activation_revisions"]
            or [row["revision"] for row in canary_revisions]
                != values["canary_revisions"]
            or [row.get("control_plane_approval_id") for row in members]
                != values["control_plane_approval_ids"]
            or [row.get("approver_id") for row in members]
                != values["approver_ids"]
        ):
            raise core.TransitionKernelError(
                "activation finalization address diverged from preparation"
            )
        sidecar_selected = context.exact(
            "policy_authority_activation_evidence_bindings",
            {"preparation_digest": preparation_digest},
        )
        sidecar = _row(sidecar_selected)
        decision_statement, binding, binding_digest = (
            _consumed_decision_gate_statement(
                context,
                evidence_digest=core.require_digest(
                    sidecar.get("evidence_digest"),
                    "activation decision-gate evidence",
                ),
                consumed_operation_id=core.require_text(
                    sidecar.get("consumed_operation_id"),
                    "activation preparation operation",
                    maximum_bytes=256,
                ),
            )
        )
        if (
            sidecar.get("activation_attempt_id")
                != values["activation_attempt_id"]
            or sidecar.get("binding_digest") != binding_digest
            or sidecar.get("evidence_chain_digest")
                != decision_statement["evidenceChainDigest"]
            or sidecar.get(
                "generation_publication_envelope_digest"
            )
                != preparation_input[
                    "generationPublicationEnvelopeDigest"
                ]
            or sidecar.get("status") not in {"prepared", "finalized"}
            or context.exact(
                "policy_activation_aborts",
                {"preparation_digest": preparation_digest},
            ).get("present") is True
        ):
            raise core.TransitionKernelError(
                "activation finalization evidence is not authoritative"
            )
        _row(
            context.exact(
                "policy_shadow_generation_publications",
                {
                    "generation_publication_envelope_digest":
                        sidecar[
                            "generation_publication_envelope_digest"
                        ]
                },
            )
        )
        _validate_activation_publication_projection(
            receipt=publication_receipt,
            activation=activation,
            activation_revisions=activation_revisions,
            canary_revisions=canary_revisions,
            decision_statement=decision_statement,
            binding=binding,
        )
        existing_finalization = context.exact(
            "policy_activation_finalizations",
            {"preparation_digest": preparation_digest},
        )
        if existing_finalization.get("present") is True:
            finalization = _row(existing_finalization)
            stored_identities = _list(
                json.loads(
                    str(finalization["inclusion_identity_set_json"])
                ),
                "stored activation inclusion identities",
                maximum=7,
            )
            if (
                [
                    item.get("inclusionReceiptEnvelopeDigest")
                    for item in stored_identities
                    if isinstance(item, Mapping)
                ]
                    != values["inclusion_digests"]
                or sidecar.get("status") != "finalized"
                or finalization.get("preparation_input_digest")
                    != preparation["preparation_input_digest"]
            ):
                raise core.TransitionKernelError(
                    "activation finalization replay diverged"
                )
            return core.KernelTransition(
                mutations=(),
                result={
                    "ok": True,
                    "idempotent": True,
                    "status": "committed",
                    **finalization,
                },
                work_units=24,
            )
        now_epoch_ns = _database_epoch_ns(context.database_now)
        if now_epoch_ns >= int(preparation["expires_at_epoch_ns"]):
            raise core.TransitionKernelError(
                "activation preparation expired before finalization"
            )
        attempt_selected = context.exact(
            "policy_activation_attempts",
            {
                "activation_attempt_id":
                    values["activation_attempt_id"]
            },
        )
        if _row(attempt_selected) != activation:
            raise core.TransitionKernelError(
                "activation attempt changed after preparation"
            )
        if _row(
            context.exact(
                "policy_activation_approvals",
                {"approval_id": preparation["approval_id"]},
            )
        ) != approval:
            raise core.TransitionKernelError(
                "activation approval changed after preparation"
            )
        _active_rbac_binding(context, values["requester_id"])
        prepared_by_purpose: dict[str, dict[str, Any]] = {}
        for ordinal in range(1, 8):
            prepared = _row(
                context.exact(
                    "policy_activation_prepared_transitions",
                    {
                        "preparation_digest": preparation_digest,
                        "transition_ordinal": ordinal,
                    },
                )
            )
            prepared_by_purpose[
                str(prepared["transition_purpose"])
            ] = prepared
        inclusion_identities: list[dict[str, Any]] = []
        previous_sequence: int | None = None
        previous_hash: str | None = None
        audit_store: str | None = None
        for index, (
            envelope_digest,
            prepared,
        ) in enumerate(
            zip(
                values["inclusion_digests"],
                [
                    prepared_by_purpose[purpose]
                    for purpose in (
                        "activation_prepared",
                        "canary_activating",
                        "activation_approved",
                        "activation_publishing",
                        "publication_committed",
                        "activation_committed",
                        "canary_active",
                    )
                ],
                strict=True,
            ),
            start=1,
        ):
            receipt = _row(
                context.exact(
                    "policy_authority_audit_inclusion_receipts",
                    {
                        "inclusion_receipt_envelope_digest":
                            envelope_digest
                    },
                )
            )
            sequence = core.require_integer(
                receipt.get("audit_sequence"),
                "activation audit inclusion sequence",
                minimum=1,
                maximum=_SIGNED_BIGINT_MAX,
            )
            if (
                receipt.get("transition_digest")
                    != prepared.get("transition_digest")
                or receipt.get("outbox_id")
                    != prepared.get("outbox_id")
                or receipt.get("outbox_event_digest")
                    != prepared.get("outbox_event_digest")
                or receipt.get("audit_ledger_namespace")
                    != "catchplate.policy-authority"
                or receipt.get("signing_key_id")
                    != receipt.get(
                        "audit_signer_public_key_digest"
                    )
                or audit_store not in {
                    None,
                    receipt.get("audit_store_identity_digest"),
                }
                or previous_sequence is not None
                and sequence != previous_sequence + 1
                or index > 1
                and receipt.get("previous_audit_event_hash")
                    != previous_hash
            ):
                raise core.TransitionKernelError(
                    "activation inclusion set is not exact"
                )
            audit_store = str(
                receipt["audit_store_identity_digest"]
            )
            previous_sequence = sequence
            previous_hash = core.require_digest(
                receipt["audit_event_hash"],
                "activation audit event",
            )
            inclusion_identities.append(
                {
                    "purpose": prepared["transition_purpose"],
                    "transitionDigest":
                        prepared["transition_digest"],
                    "auditEventHash":
                        receipt["audit_event_hash"],
                    "auditSequence": sequence,
                    "inclusionRootDigest":
                        receipt["inclusion_root_digest"],
                    "inclusionReceiptEnvelopeDigest":
                        envelope_digest,
                }
            )
        inclusion_json = core.canonical_bytes(
            inclusion_identities
        ).decode("ascii")
        inclusion_digest = core.framed_digest(
            "catchplate.policyActivationAuditInclusionSet/v2",
            inclusion_json.encode("ascii"),
        )
        high_water_selected = context.exact(
            "policy_high_water",
            {"scope": "active"},
        )
        high_water = _row(high_water_selected)
        high_water_material = {
            "policyHash": high_water.get("policy_hash"),
            "policyId": high_water.get("policy_id"),
            "rollbackEpoch": high_water.get("rollback_epoch"),
            "scope": "active",
            "sequence": high_water.get("sequence"),
        }
        if (
            _sha256(core.canonical_bytes(high_water_material))
                != preparation["expected_high_water_digest"]
            or high_water.get("policy_hash")
                != preparation["predecessor_policy_hash"]
            or high_water.get("sequence")
                != activation["expected_active_policy_sequence"]
            or high_water.get("rollback_epoch")
                != activation["expected_active_rollback_epoch"]
            or high_water.get("policy_id")
                != publication_receipt["policy_id"]
        ):
            raise core.TransitionKernelError(
                "activation predecessor high-water changed"
            )
        canary_head_selected = context.exact(
            "policy_canary_heads",
            {"canary_id": values["canary_id"]},
        )
        canary_head = _row(canary_head_selected)
        if (
            canary_head.get("status") != "ready"
            or canary_head.get("head_revision")
                != preparation["prepared_canary_revision"]
            or canary_head.get("head_state_digest")
                != preparation["prepared_canary_state_digest"]
        ):
            raise core.TransitionKernelError(
                "activation canary predecessor changed"
            )
        mutations: list[dict[str, Any]] = []
        now_iso = _database_iso(context.database_now)
        for index, (
            member,
            control_approval_id,
            approver_id,
        ) in enumerate(
            zip(
                members,
                values["control_plane_approval_ids"],
                values["approver_ids"],
                strict=True,
            ),
            start=1,
        ):
            stored_member = _row(
                context.exact(
                    "policy_activation_approval_members",
                    {
                        "approval_id": preparation["approval_id"],
                        "member_ordinal": index,
                    },
                )
            )
            control_selected = context.exact(
                "control_plane_approvals",
                {"id": control_approval_id},
            )
            control = _row(control_selected)
            _active_rbac_binding(context, approver_id)
            if (
                stored_member != member
                or control.get("status") != "approved"
                or control.get("action")
                    != "policy.candidate.activate"
                or control.get("resource_id")
                    != values["canary_id"]
                or control.get("payload_digest")
                    != activation["approval_context_digest"]
                or control.get("requester_id")
                    != values["requester_id"]
                or control.get("approved_by") != approver_id
                or control.get(
                    "approver_webauthn_credential_id"
                )
                    != member[
                        "approver_webauthn_credential_id"
                    ]
                or str(control.get("expires_at")) <= now_iso
                or approver_id == values["requester_id"]
            ):
                raise core.TransitionKernelError(
                    "activation approval authority changed"
                )
            mutations.append(
                core.mutation(
                    operation=self.operation,
                    selected=control_selected,
                    row={
                        **control,
                        "status": "consumed",
                        "consumed_by": consumption["consumed_by"],
                        "consumed_at": consumption["consumed_at"],
                    },
                )
            )
        consumption_mutation = _immutable_mutation(
            context,
            table="policy_activation_approval_consumptions",
            key={"approval_id": preparation["approval_id"]},
            row=consumption,
        )
        if consumption_mutation is not None:
            mutations.append(consumption_mutation)
        activation_stored_rows: list[dict[str, Any]] = []
        activation_purposes = (
            "activation_prepared",
            "activation_approved",
            "activation_publishing",
            "activation_committed",
        )
        for revision, purpose in zip(
            activation_revisions,
            activation_purposes,
            strict=True,
        ):
            stored = _stored_revision(
                revision,
                prepared_by_purpose[purpose],
                entity_kind="activation",
            )
            activation_stored_rows.append(stored)
            mutation_value = _immutable_mutation(
                context,
                table="policy_activation_revisions",
                key={
                    "activation_attempt_id":
                        values["activation_attempt_id"],
                    "revision": revision["revision"],
                },
                row=stored,
            )
            if mutation_value is not None:
                mutations.append(mutation_value)
        activation_head_selected = context.exact(
            "policy_activation_heads",
            {
                "activation_attempt_id":
                    values["activation_attempt_id"]
            },
        )
        activation_head = {
            "activation_attempt_id":
                values["activation_attempt_id"],
            "head_revision": activation_revisions[-1]["revision"],
            "head_state_digest":
                activation_revisions[-1]["state_digest"],
            "status": "committed",
            "unresolved_indeterminate": 0,
            "updated_at_epoch_ns":
                activation_revisions[-1]["created_at_epoch_ns"],
        }
        mutations.append(
            core.mutation(
                operation=self.operation,
                selected=activation_head_selected,
                row=activation_head,
            )
        )
        canary_purposes = ("canary_activating", "canary_active")
        for revision, purpose in zip(
            canary_revisions,
            canary_purposes,
            strict=True,
        ):
            stored = _stored_revision(
                revision,
                prepared_by_purpose[purpose],
                entity_kind="canary",
            )
            mutation_value = _immutable_mutation(
                context,
                table="policy_canary_revisions",
                key={
                    "canary_id": values["canary_id"],
                    "revision": revision["revision"],
                },
                row=stored,
            )
            if mutation_value is not None:
                mutations.append(mutation_value)
        final_canary_head = {
            "canary_id": values["canary_id"],
            "head_revision": canary_revisions[-1]["revision"],
            "head_state_digest":
                canary_revisions[-1]["state_digest"],
            "status": "active",
            "updated_at_epoch_ns":
                canary_revisions[-1]["created_at_epoch_ns"],
        }
        mutations.append(
            core.mutation(
                operation=self.operation,
                selected=canary_head_selected,
                row=final_canary_head,
            )
        )
        rollback_digest = values["rollback_authorization_digest"]
        if rollback_digest is not None:
            rollback = _row(
                context.exact(
                    "policy_activation_rollback_authorities",
                    {
                        "rollback_authorization_payload_digest":
                            rollback_digest
                    },
                )
            )
            if (
                context.exact(
                    (
                        "policy_activation_"
                        "rollback_authority_revocations"
                    ),
                    {
                        "rollback_authorization_payload_digest":
                            rollback_digest
                    },
                ).get("present") is True
                or int(rollback["expires_at_epoch_ns"]) <= now_epoch_ns
            ):
                raise core.TransitionKernelError(
                    "activation rollback authority is not current"
                )
            rollback_material = {
                "activationAttemptId":
                    values["activation_attempt_id"],
                "approvalContextDigest":
                    activation["approval_context_digest"],
                "consumedAtEpochNs": now_epoch_ns,
                "consumedBy": values["requester_id"],
                "expectedHighWaterDigest":
                    activation["expected_high_water_digest"],
                "publicationRevision":
                    activation["publication_revision"],
                "readinessPayloadDigest":
                    activation["readiness_payload_digest"],
                "rollbackAuthorizationPayloadDigest":
                    rollback_digest,
                "webauthnChallengeContextDigest":
                    approval["webauthn_challenge_context_digest"],
            }
            rollback_consumption = {
                "rollback_authorization_payload_digest":
                    rollback_digest,
                "rollback_authorization_envelope_digest":
                    rollback[
                        "rollback_authorization_envelope_digest"
                    ],
                "activation_attempt_id":
                    values["activation_attempt_id"],
                "readiness_payload_digest":
                    activation["readiness_payload_digest"],
                "approval_context_digest":
                    activation["approval_context_digest"],
                "webauthn_challenge_context_digest":
                    approval["webauthn_challenge_context_digest"],
                "expected_high_water_digest":
                    activation["expected_high_water_digest"],
                "publication_revision":
                    activation["publication_revision"],
                "consumed_by": values["requester_id"],
                "consumed_at_epoch_ns": now_epoch_ns,
                "consumption_digest": core.framed_digest(
                    "catchplate.policyRollbackConsumption/v2",
                    core.canonical_bytes(rollback_material),
                ),
            }
            mutation_value = _immutable_mutation(
                context,
                table="policy_activation_rollback_consumptions",
                key={
                    "rollback_authorization_payload_digest":
                        rollback_digest
                },
                row=rollback_consumption,
            )
            if mutation_value is not None:
                mutations.append(mutation_value)
        publication_selected = context.exact(
            "policy_publications",
            {"policy_hash": activation["candidate_policy_hash"]},
        )
        publication = {
            "policy_hash": activation["candidate_policy_hash"],
            "scope": "active",
            "policy_id": publication_receipt["policy_id"],
            "sequence": activation["candidate_policy_sequence"],
            "rollback_epoch":
                activation["candidate_rollback_epoch"],
            "status": "committed",
            "previous_policy_hash":
                activation["predecessor_policy_hash"],
            "created_at": now_iso,
            "committed_at": now_iso,
            "updated_at": now_iso,
        }
        publication_mutation = _immutable_mutation(
            context,
            table="policy_publications",
            key={"policy_hash": activation["candidate_policy_hash"]},
            row=publication,
        )
        if publication_mutation is not None:
            mutations.append(publication_mutation)
        committed_high_water = {
            "scope": "active",
            "policy_id": publication_receipt["policy_id"],
            "sequence": activation["candidate_policy_sequence"],
            "rollback_epoch":
                activation["candidate_rollback_epoch"],
            "policy_hash": activation["candidate_policy_hash"],
            "updated_at": now_iso,
        }
        high_water_after_digest = _sha256(
            core.canonical_bytes(
                {
                    "policyHash":
                        committed_high_water["policy_hash"],
                    "policyId": committed_high_water["policy_id"],
                    "rollbackEpoch":
                        committed_high_water["rollback_epoch"],
                    "scope": "active",
                    "sequence": committed_high_water["sequence"],
                }
            )
        )
        if (
            high_water_after_digest
                != binding["policyHighWaterAfterDigest"]
            or high_water_after_digest
                != publication_receipt["high_water_after_digest"]
        ):
            raise core.TransitionKernelError(
                "activation committed high-water digest diverged"
            )
        mutations.append(
            core.mutation(
                operation=self.operation,
                selected=high_water_selected,
                row=committed_high_water,
            )
        )
        stored_publication_receipt = {
            **publication_receipt,
            "created_transition_digest":
                prepared_by_purpose[
                    "publication_committed"
                ]["transition_digest"],
        }
        receipt_mutation = _immutable_mutation(
            context,
            table="policy_activation_publication_receipts",
            key={
                "publication_receipt_envelope_digest":
                    values[
                        "publication_receipt_envelope_digest"
                    ]
            },
            row=stored_publication_receipt,
        )
        if receipt_mutation is not None:
            mutations.append(receipt_mutation)
        finalized_snapshot = {
            "schema":
                "catchplate.policyActivationFinalizedAuthoritySnapshot/v2",
            "activation_attempt_id":
                values["activation_attempt_id"],
            "preparation_digest": preparation_digest,
            "publication": publication,
            "high_water": committed_high_water,
            "canary_head": final_canary_head,
            "activation_head": activation_head,
            "decision_gate_evidence_chain_digest":
                sidecar["evidence_chain_digest"],
        }
        snapshot_json = core.canonical_bytes(
            finalized_snapshot
        ).decode("ascii")
        snapshot_digest = core.framed_digest(
            (
                "catchplate."
                "policyActivationFinalizedAuthoritySnapshot/v2"
            ),
            snapshot_json.encode("ascii"),
        )
        finalization_material = {
            "activationAttemptId": values["activation_attempt_id"],
            "finalizedAuthoritySnapshotDigest": snapshot_digest,
            "finalizedAtEpochNs": now_epoch_ns,
            "highWaterAfterDigest": high_water_after_digest,
            "inclusionIdentitySetDigest": inclusion_digest,
            "preparationDigest": preparation_digest,
            "preparationInputDigest":
                preparation["preparation_input_digest"],
            "publicationReceiptPayloadDigest":
                publication_receipt[
                    "publication_receipt_payload_digest"
                ],
        }
        finalization = {
            "preparation_digest": preparation_digest,
            "activation_attempt_id":
                values["activation_attempt_id"],
            "preparation_input_digest":
                preparation["preparation_input_digest"],
            "inclusion_identity_set_json": inclusion_json,
            "inclusion_identity_set_digest": inclusion_digest,
            "publication_receipt_payload_digest":
                publication_receipt[
                    "publication_receipt_payload_digest"
                ],
            "high_water_after_digest": high_water_after_digest,
            "finalized_authority_snapshot_json": snapshot_json,
            "finalized_authority_snapshot_digest":
                snapshot_digest,
            "finalization_digest": core.framed_digest(
                "catchplate.policyActivationFinalization/v2",
                core.canonical_bytes(finalization_material),
            ),
            "finalized_at_epoch_ns": now_epoch_ns,
        }
        finalization_mutation = _immutable_mutation(
            context,
            table="policy_activation_finalizations",
            key={"preparation_digest": preparation_digest},
            row=finalization,
        )
        if finalization_mutation is not None:
            mutations.append(finalization_mutation)
        sidecar_after = {
            **sidecar,
            "status": "finalized",
            "finalized_at_epoch_ns": now_epoch_ns,
        }
        mutations.append(
            core.mutation(
                operation=self.operation,
                selected=sidecar_selected,
                row=sidecar_after,
            )
        )
        return core.KernelTransition(
            mutations=tuple(mutations),
            result={
                "ok": True,
                "idempotent": False,
                "status": "committed",
                **finalization,
            },
            work_units=224,
        )


def _genesis_prepare_arguments(
    arguments: Mapping[str, Any],
) -> tuple[dict[str, Any], str, str]:
    core.require_exact_arguments(arguments, _GENESIS_PREPARE_FIELDS)
    evidence_digest = core.require_digest(
        arguments["policySignatureEvidenceDigest"],
        "policy genesis signature evidence",
    )
    record = _genesis_record(arguments["record"])
    input_digest = core.framed_digest(
        "catchplate.policyAuthorityGenesisPreparationInput/v2",
        core.canonical_bytes(record),
    )
    return record, evidence_digest, input_digest


def _genesis_record(value):
    """Shared original-only grammar; neither branch gains evidence authority."""
    record = _mapping(value, "policy genesis record", fields=_GENESIS_RECORD_FIELDS)
    for field in (
        "genesis_preparation_digest",
        "policy_hash",
        "high_water_digest",
        "genesis_envelope_digest",
        "genesis_payload_digest",
        "signing_key_id",
        "signature_digest",
    ):
        core.require_digest(record.get(field), f"policy genesis {field}")
    policy_id = core.require_text(
        record.get("policy_id"),
        "policy genesis policy identity",
        maximum_bytes=256,
    )
    sequence = core.require_integer(
        record.get("policy_sequence"),
        "policy genesis sequence",
        minimum=1,
        maximum=_SIGNED_BIGINT_MAX,
    )
    rollback_epoch = core.require_integer(
        record.get("rollback_epoch"),
        "policy genesis rollback epoch",
        minimum=1,
        maximum=_SIGNED_BIGINT_MAX,
    )
    prepared_at = core.require_integer(
        record.get("prepared_at_epoch_ns"),
        "policy genesis preparation time",
        minimum=0,
        maximum=_SIGNED_BIGINT_MAX,
    )
    expires_at = core.require_integer(
        record.get("expires_at_epoch_ns"),
        "policy genesis expiry",
        minimum=1,
        maximum=_SIGNED_BIGINT_MAX,
    )
    if (
        prepared_at >= expires_at
        or record.get("signature_algorithm") != "Ed25519"
        or not record.get("signature")
    ):
        raise core.TransitionKernelError(
            "policy genesis validity is not exact"
        )
    envelope = _mapping_json(
        record.get("genesis_envelope_json"),
        "policy genesis envelope",
    )
    payload = _mapping_json(
        record.get("genesis_payload_json"),
        "policy genesis payload",
    )
    if (
        _sha256(core.canonical_bytes(envelope))
            != record["genesis_envelope_digest"]
        or _sha256(core.canonical_bytes(payload))
            != record["genesis_payload_digest"]
        or _sha256(
            core.canonical_bytes(
                {
                    "policyHash": record["policy_hash"],
                    "policyId": policy_id,
                    "rollbackEpoch": rollback_epoch,
                    "scope": "active",
                    "sequence": sequence,
                }
            )
        )
            != record["high_water_digest"]
    ):
        raise core.TransitionKernelError(
            "policy genesis canonical digest changed"
        )
    return record


@dataclass(frozen=True, slots=True)
class _PolicyGenesisPrepareKernel:
    operation: str = "policy.genesis.prepare"
    handler: str = "catchplate_policy_authority_genesis_prepare"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "policy.genesis.prepare",
        "catchplate_policy_authority_genesis_prepare",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        from catchplate import authority_transition_policy_genesis as successor
        if successor.selected(self.operation, arguments):
            return successor.queries(self.operation, arguments=arguments,
                database_now=database_now, request_digest=request_digest)
        core.require_digest(
            request_digest,
            "policy genesis preparation request",
        )
        record, evidence_digest, _ = _genesis_prepare_arguments(
            arguments
        )
        stage = _audit_stage(
            event_type="policy.authority.genesis.prepared",
            entity_kind="activation_genesis",
            entity_id=str(record["policy_hash"]),
            entity_revision=1,
            state_digest=str(record["genesis_preparation_digest"]),
            previous_state_digest=None,
            actor_id=str(record["prepared_by"]),
            evidence={
                "highWaterDigest": record["high_water_digest"],
                "policyHash": record["policy_hash"],
            },
            created_at_epoch_ns=int(record["prepared_at_epoch_ns"]),
            created_at=_database_iso(database_now),
        )
        return (
            _exact_query(
                operation=self.operation,
                name="genesis_preparation",
                table="policy_authority_genesis_preparations",
                key={
                    "genesis_preparation_digest":
                        record["genesis_preparation_digest"]
                },
            ),
            _exact_query(
                operation=self.operation,
                name="genesis_finalization",
                table="policy_authority_genesis_finalizations",
                key={
                    "genesis_preparation_digest":
                        record["genesis_preparation_digest"]
                },
            ),
            _exact_query(
                operation=self.operation,
                name="active_high_water",
                table="policy_high_water",
                key={"scope": "active"},
            ),
            _exact_empty_page_query(
                operation=self.operation,
                name="active_publication_page",
                table="policy_publications",
                predicates={"scope": "active"},
                order_by=("policy_hash",),
            ),
            _exact_query(
                operation=self.operation,
                name="signature_evidence",
                table="policy_authority_external_evidence_receipts",
                key={"evidence_digest": evidence_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="genesis_outbox",
                table="metadata_audit_outbox",
                key={"id": stage["outbox"]["id"]},
            ),
            _exact_query(
                operation=self.operation,
                name="genesis_transition",
                table="policy_authority_transition_audits",
                key={
                    "transition_digest":
                        stage["transition"]["transition_digest"]
                },
            ),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        from catchplate import authority_transition_policy_genesis as successor
        if successor.selected(self.operation, context.arguments):
            return successor.transition(context)
        record, evidence_digest, input_digest = (
            _genesis_prepare_arguments(context.arguments)
        )
        preparation_digest = record[
            "genesis_preparation_digest"
        ]
        selected = context.exact(
            "policy_authority_genesis_preparations",
            {"genesis_preparation_digest": preparation_digest},
        )
        operation_id = _operation_id(
            self.operation,
            context.request_digest,
        )
        if selected.get("present") is True:
            stored = _row(selected)
            evidence = _row(
                context.exact(
                    "policy_authority_external_evidence_receipts",
                    {"evidence_digest": evidence_digest},
                )
            )
            _validated_input_evidence(
                context,
                evidence_digest=evidence_digest,
                input_digest=input_digest,
                subject_digest=record["policy_hash"],
                consumed_operation_id=operation_id,
            )
            if (
                any(
                    stored.get(field) != value
                    for field, value in record.items()
                )
                or stored.get("record_binding_digest")
                    != evidence.get("binding_digest")
            ):
                raise core.TransitionKernelError(
                    "policy genesis preparation replay diverged"
                )
            return core.KernelTransition(
                mutations=(),
                result={
                    "ok": True,
                    "idempotent": True,
                    **stored,
                },
                work_units=12,
            )
        if (
            context.exact(
                "policy_authority_genesis_finalizations",
                {"genesis_preparation_digest": preparation_digest},
            ).get("present") is True
            or context.exact(
                "policy_high_water",
                {"scope": "active"},
            ).get("present") is True
            or context.present_rows("policy_publications")
        ):
            raise core.TransitionKernelError(
                "policy genesis requires an empty authority"
            )
        now_epoch_ns = _database_epoch_ns(context.database_now)
        if not (
            int(record["prepared_at_epoch_ns"])
            <= now_epoch_ns
            < int(record["expires_at_epoch_ns"])
        ):
            raise core.TransitionKernelError(
                "policy genesis is outside its validity interval"
            )
        _, binding_digest = _validated_input_evidence(
            context,
            evidence_digest=evidence_digest,
            input_digest=input_digest,
            subject_digest=record["policy_hash"],
        )
        evidence = _row(
            context.exact(
                "policy_authority_external_evidence_receipts",
                {"evidence_digest": evidence_digest},
            )
        )
        stage = _audit_stage(
            event_type="policy.authority.genesis.prepared",
            entity_kind="activation_genesis",
            entity_id=str(record["policy_hash"]),
            entity_revision=1,
            state_digest=str(preparation_digest),
            previous_state_digest=None,
            actor_id=str(record["prepared_by"]),
            evidence={
                "highWaterDigest": record["high_water_digest"],
                "policyHash": record["policy_hash"],
            },
            created_at_epoch_ns=int(record["prepared_at_epoch_ns"]),
            created_at=_database_iso(context.database_now),
        )
        stored = {
            **record,
            "evidence_kind": "authority_genesis",
            "record_binding_digest": binding_digest,
            "verification_receipt_digest":
                evidence["receipt_digest"],
            "genesis_transition_digest":
                stage["transition"]["transition_digest"],
        }
        return core.KernelTransition(
            mutations=(
                context.consume_evidence(
                    evidence_type="policy-signature-verification/v1",
                    evidence_digest=evidence_digest,
                    binding_digest=binding_digest,
                    operation_id=operation_id,
                ),
                *_fresh_audit_mutations(
                    context,
                    operation_id=operation_id,
                    outbox_rows=(stage["outbox"],),
                ),
                core.mutation(
                    operation=self.operation,
                    selected=context.exact(
                        "policy_authority_transition_audits",
                        {
                            "transition_digest":
                                stage["transition"][
                                    "transition_digest"
                                ]
                        },
                    ),
                    row=stage["transition"],
                ),
                core.mutation(
                    operation=self.operation,
                    selected=selected,
                    row=stored,
                ),
            ),
            result={
                "ok": True,
                "idempotent": False,
                **stored,
                "audit_submission": stage["transition"],
            },
            work_units=64,
        )


def _genesis_finalize_arguments(
    arguments: Mapping[str, Any],
) -> tuple[str, dict[str, Any], str, str]:
    core.require_exact_arguments(arguments, _GENESIS_FINALIZE_FIELDS)
    preparation_digest = core.require_digest(
        arguments["genesisPreparationDigest"],
        "policy genesis preparation",
    )
    inclusion = _mapping(
        arguments["inclusionReceipt"],
        "policy genesis inclusion receipt",
    )
    envelope_digest = core.require_digest(
        inclusion.get("inclusion_receipt_envelope_digest"),
        "policy genesis inclusion envelope",
    )
    evidence_digest = core.require_digest(
        arguments["inclusionEvidenceDigest"],
        "policy genesis inclusion evidence",
    )
    audit_store_identity_digest = core.require_digest(
        arguments["auditStoreIdentityDigest"],
        "policy genesis audit store",
    )
    return (
        preparation_digest,
        inclusion,
        evidence_digest,
        audit_store_identity_digest,
    )


@dataclass(frozen=True, slots=True)
class _PolicyGenesisFinalizeKernel:
    operation: str = "policy.genesis.finalize"
    handler: str = "catchplate_policy_authority_genesis_finalize"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "policy.genesis.finalize",
        "catchplate_policy_authority_genesis_finalize",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        from catchplate import authority_transition_policy_genesis as successor
        if successor.selected(self.operation, arguments):
            return successor.queries(self.operation, arguments=arguments,
                database_now=database_now, request_digest=request_digest)
        del database_now
        core.require_digest(
            request_digest,
            "policy genesis finalization request",
        )
        (
            preparation_digest,
            inclusion,
            evidence_digest,
            audit_store_identity_digest,
        ) = _genesis_finalize_arguments(arguments)
        return (
            _exact_query(
                operation=self.operation,
                name="genesis_preparation",
                table="policy_authority_genesis_preparations",
                key={
                    "genesis_preparation_digest":
                        preparation_digest
                },
            ),
            _exact_query(
                operation=self.operation,
                name="genesis_finalization",
                table="policy_authority_genesis_finalizations",
                key={
                    "genesis_preparation_digest":
                        preparation_digest
                },
            ),
            _exact_query(
                operation=self.operation,
                name="inclusion_evidence",
                table="policy_authority_external_evidence_receipts",
                key={"evidence_digest": evidence_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="inclusion_receipt",
                table="policy_authority_audit_inclusion_receipts",
                key={
                    "inclusion_receipt_envelope_digest":
                        inclusion[
                            "inclusion_receipt_envelope_digest"
                        ]
                },
            ),
            _exact_query(
                operation=self.operation,
                name="inclusion_head",
                table="policy_authority_audit_inclusion_heads",
                key={
                    "audit_store_identity_digest":
                        audit_store_identity_digest
                },
            ),
            _exact_query(
                operation=self.operation,
                name="active_high_water",
                table="policy_high_water",
                key={"scope": "active"},
            ),
            _exact_query(
                operation=self.operation,
                name="genesis_publication",
                table="policy_publications",
                key={
                    "policy_hash":
                        core.SelectedRowFieldReference(
                            table=(
                                "policy_authority_"
                                "genesis_preparations"
                            ),
                            key={
                                "genesis_preparation_digest":
                                    preparation_digest
                            },
                            column="policy_hash",
                        )
                },
            ),
            _exact_empty_page_query(
                operation=self.operation,
                name="active_publication_page",
                table="policy_publications",
                predicates={"scope": "active"},
                order_by=("policy_hash",),
            ),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        from catchplate import authority_transition_policy_genesis as successor
        if successor.selected(self.operation, context.arguments):
            return successor.transition(context)
        (
            preparation_digest,
            supplied_inclusion,
            evidence_digest,
            audit_store_identity_digest,
        ) = _genesis_finalize_arguments(context.arguments)
        preparation = _row(
            context.exact(
                "policy_authority_genesis_preparations",
                {
                    "genesis_preparation_digest":
                        preparation_digest
                },
            )
        )
        operation_id = _operation_id(
            self.operation,
            context.request_digest,
        )
        existing = context.exact(
            "policy_authority_genesis_finalizations",
            {"genesis_preparation_digest": preparation_digest},
        )
        replay = existing.get("present") is True
        _, receipt, binding_digest = _inclusion_statement(
            context,
            evidence_digest=evidence_digest,
            preparation_digest=preparation_digest,
            envelope_digest=supplied_inclusion[
                "inclusion_receipt_envelope_digest"
            ],
            consumed_operation_id=operation_id if replay else None,
        )
        if (
            receipt != supplied_inclusion
            or receipt.get("transition_digest")
                != preparation["genesis_transition_digest"]
            or receipt.get("audit_store_identity_digest")
                != audit_store_identity_digest
            or receipt.get("audit_ledger_namespace")
                != "catchplate.policy-authority"
            or receipt.get("signing_key_id")
                != receipt.get("audit_signer_public_key_digest")
        ):
            raise core.TransitionKernelError(
                "policy genesis inclusion is not exact"
            )
        if replay:
            finalization = _row(existing)
            stored_receipt = _row(
                context.exact(
                    "policy_authority_audit_inclusion_receipts",
                    {
                        "inclusion_receipt_envelope_digest":
                            receipt[
                                "inclusion_receipt_envelope_digest"
                            ]
                    },
                )
            )
            if (
                stored_receipt != receipt
                or finalization.get(
                    "inclusion_receipt_envelope_digest"
                )
                    != receipt[
                        "inclusion_receipt_envelope_digest"
                    ]
            ):
                raise core.TransitionKernelError(
                    "policy genesis finalization replay diverged"
                )
            return core.KernelTransition(
                mutations=(),
                result={
                    "ok": True,
                    "idempotent": True,
                    **finalization,
                },
                work_units=12,
            )
        now_epoch_ns = _database_epoch_ns(context.database_now)
        if now_epoch_ns >= int(preparation["expires_at_epoch_ns"]):
            raise core.TransitionKernelError(
                "policy genesis preparation expired"
            )
        if (
            context.exact(
                "policy_high_water",
                {"scope": "active"},
            ).get("present") is True
            or context.present_rows("policy_publications")
        ):
            raise core.TransitionKernelError(
                "policy genesis authority is no longer empty"
            )
        head_selected = context.exact(
            "policy_authority_audit_inclusion_heads",
            {
                "audit_store_identity_digest":
                    audit_store_identity_digest
            },
        )
        if head_selected.get("present") is True:
            head = _row(head_selected)
            if (
                receipt.get("audit_sequence")
                    != int(head["audit_sequence"]) + 1
                or receipt.get("previous_audit_event_hash")
                    != head["audit_event_hash"]
            ):
                raise core.TransitionKernelError(
                    "policy genesis inclusion head changed"
                )
        elif (
            receipt.get("audit_sequence") != 1
            or receipt.get("previous_audit_event_hash") is not None
        ):
            raise core.TransitionKernelError(
                "policy genesis inclusion does not start its ledger"
            )
        finalization_material = {
            "genesisPreparationDigest": preparation_digest,
            "highWaterDigest": preparation["high_water_digest"],
            "inclusionReceiptEnvelopeDigest":
                receipt["inclusion_receipt_envelope_digest"],
            "finalizedAtEpochNs": now_epoch_ns,
        }
        finalization = {
            "genesis_preparation_digest": preparation_digest,
            "policy_id": preparation["policy_id"],
            "policy_sequence": preparation["policy_sequence"],
            "rollback_epoch": preparation["rollback_epoch"],
            "policy_hash": preparation["policy_hash"],
            "high_water_digest": preparation["high_water_digest"],
            "inclusion_receipt_envelope_digest":
                receipt["inclusion_receipt_envelope_digest"],
            "genesis_transition_digest":
                preparation["genesis_transition_digest"],
            "finalization_digest": core.framed_digest(
                "catchplate.policyAuthorityGenesisFinalization/v2",
                core.canonical_bytes(finalization_material),
            ),
            "finalized_at_epoch_ns": now_epoch_ns,
        }
        now_iso = _database_iso(context.database_now)
        publication = {
            "policy_hash": preparation["policy_hash"],
            "scope": "active",
            "policy_id": preparation["policy_id"],
            "sequence": preparation["policy_sequence"],
            "rollback_epoch": preparation["rollback_epoch"],
            "status": "committed",
            "previous_policy_hash": None,
            "created_at": now_iso,
            "committed_at": now_iso,
            "updated_at": now_iso,
        }
        high_water = {
            "scope": "active",
            "policy_id": preparation["policy_id"],
            "sequence": preparation["policy_sequence"],
            "rollback_epoch": preparation["rollback_epoch"],
            "policy_hash": preparation["policy_hash"],
            "updated_at": now_iso,
        }
        next_head = {
            "audit_store_identity_digest":
                audit_store_identity_digest,
            "audit_ledger_namespace":
                receipt["audit_ledger_namespace"],
            "audit_signer_public_key_digest":
                receipt["audit_signer_public_key_digest"],
            "signing_key_id": receipt["signing_key_id"],
            "audit_sequence": receipt["audit_sequence"],
            "audit_event_hash": receipt["audit_event_hash"],
            "inclusion_root_digest":
                receipt["inclusion_root_digest"],
            "inclusion_receipt_envelope_digest":
                receipt["inclusion_receipt_envelope_digest"],
            "updated_at_epoch_ns": now_epoch_ns,
        }
        receipt_selected = context.exact(
            "policy_authority_audit_inclusion_receipts",
            {
                "inclusion_receipt_envelope_digest":
                    receipt["inclusion_receipt_envelope_digest"]
            },
        )
        return core.KernelTransition(
            mutations=(
                context.consume_evidence(
                    evidence_type="audit-inclusion/v1",
                    evidence_digest=evidence_digest,
                    binding_digest=binding_digest,
                    operation_id=operation_id,
                ),
                core.mutation(
                    operation=self.operation,
                    selected=receipt_selected,
                    row=receipt,
                ),
                core.mutation(
                    operation=self.operation,
                    selected=head_selected,
                    row=next_head,
                ),
                core.mutation(
                    operation=self.operation,
                    selected=context.exact(
                        "policy_publications",
                        {"policy_hash": preparation["policy_hash"]},
                    ),
                    row=publication,
                ),
                core.mutation(
                    operation=self.operation,
                    selected=context.exact(
                        "policy_high_water",
                        {"scope": "active"},
                    ),
                    row=high_water,
                ),
                core.mutation(
                    operation=self.operation,
                    selected=existing,
                    row=finalization,
                ),
            ),
            result={
                "ok": True,
                "idempotent": False,
                **finalization,
            },
            work_units=72,
        )


def _rbac_mutate_arguments(
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    core.require_exact_arguments(arguments, _RBAC_MUTATE_FIELDS)
    subject_id = core.require_text(
        arguments["subjectId"],
        "RBAC subject identity",
        maximum_bytes=1024,
    )
    actor_id = core.require_text(
        arguments["actorId"],
        "RBAC actor identity",
        maximum_bytes=1024,
    )
    status = arguments["status"]
    roles = _list(
        arguments["roles"],
        "RBAC roles",
        maximum=len(_VALID_RBAC_ROLES),
    )
    if (
        status not in {"active", "deprovisioned"}
        or any(
            not isinstance(role, str)
            or role not in _VALID_RBAC_ROLES
            for role in roles
        )
        or roles != sorted(set(roles))
        or status == "active" and not roles
        or status == "deprovisioned" and roles
    ):
        raise core.TransitionKernelError(
            "RBAC role mutation is outside the closed vocabulary"
        )
    reason = arguments["reason"]
    if reason is not None:
        reason = core.require_text(
            reason,
            "RBAC mutation reason",
            maximum_bytes=500,
        )
    return {
        "subject_id": subject_id,
        "actor_id": actor_id,
        "roles": roles,
        "status": status,
        "expected_generation": core.require_integer(
            arguments["expectedGeneration"],
            "RBAC expected generation",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX - 1,
        ),
        "reason": reason,
        "event_type": core.require_text(
            arguments["eventType"],
            "RBAC event type",
            maximum_bytes=256,
        ),
        "event": _mapping(arguments["event"], "RBAC event"),
    }


def _rbac_binding_material(
    values: Mapping[str, Any],
    *,
    generation: int,
    updated_at: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    material = {
        "subject_id": values["subject_id"],
        "roles": values["roles"],
        "status": values["status"],
        "generation": generation,
        "updated_at": updated_at,
        "updated_by": values["actor_id"],
        "reason": values["reason"],
    }
    if values["status"] == "deprovisioned":
        material["deprovisioned_at"] = updated_at
        material["deprovisioned_by"] = values["actor_id"]
    row = {
        "subject_id": values["subject_id"],
        "roles_json": core.canonical_bytes(
            values["roles"]
        ).decode("ascii"),
        "status": values["status"],
        "generation": generation,
        "binding_digest": _sha256(core.canonical_bytes(material)),
        "updated_at": updated_at,
        "updated_by": values["actor_id"],
        "reason": values["reason"],
        "deprovisioned_at": (
            updated_at
            if values["status"] == "deprovisioned"
            else None
        ),
        "deprovisioned_by": (
            values["actor_id"]
            if values["status"] == "deprovisioned"
            else None
        ),
    }
    return material, row


@dataclass(frozen=True, slots=True)
class _RbacBindingMutateKernel:
    operation: str = "rbac.binding.mutate"
    handler: str = "catchplate_policy_authority_rbac_mutate"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "rbac.binding.mutate",
        "catchplate_policy_authority_rbac_mutate",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        core.require_digest(request_digest, "RBAC mutation request")
        values = _rbac_mutate_arguments(arguments)
        now_iso = _database_iso(database_now)
        next_generation = values["expected_generation"] + 1
        _, binding = _rbac_binding_material(
            values,
            generation=next_generation,
            updated_at=now_iso,
        )
        stage = _audit_stage(
            event_type=values["event_type"],
            entity_kind="rbac_binding",
            entity_id=values["subject_id"],
            entity_revision=next_generation,
            state_digest=binding["binding_digest"],
            previous_state_digest=None,
            actor_id=values["actor_id"],
            evidence=values["event"],
            created_at_epoch_ns=_database_epoch_ns(database_now),
            created_at=now_iso,
        )
        queries: list[core.BoundedQuery] = [
            _exact_query(
                operation=self.operation,
                name="authority_state",
                table="rbac_authority_state",
                key={"authority_id": 1},
            ),
            _exact_query(
                operation=self.operation,
                name="subject_binding",
                table="rbac_role_bindings",
                key={"subject_id": values["subject_id"]},
            ),
            _exact_query(
                operation=self.operation,
                name="rbac_outbox",
                table="metadata_audit_outbox",
                key={"id": stage["outbox"]["id"]},
            ),
            _exact_query(
                operation=self.operation,
                name="rbac_transition",
                table="policy_authority_transition_audits",
                key={
                    "transition_digest":
                        stage["transition"]["transition_digest"]
                },
            ),
        ]
        if (
            values["actor_id"].startswith("oidc:")
            and values["actor_id"] != values["subject_id"]
        ):
            queries.append(
                _exact_query(
                    operation=self.operation,
                    name="actor_binding",
                    table="rbac_role_bindings",
                    key={"subject_id": values["actor_id"]},
                )
            )
        return tuple(queries)

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        values = _rbac_mutate_arguments(context.arguments)
        authority_selected = context.exact(
            "rbac_authority_state",
            {"authority_id": 1},
        )
        authority = _row(authority_selected)
        binding_selected = context.exact(
            "rbac_role_bindings",
            {"subject_id": values["subject_id"]},
        )
        previous = (
            _row(binding_selected)
            if binding_selected.get("present") is True
            else None
        )
        current_generation = core.require_integer(
            authority.get("generation"),
            "RBAC authority generation",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        )
        expected = values["expected_generation"]
        if current_generation == expected + 1 and previous is not None:
            previous_roles = json.loads(str(previous["roles_json"]))
            if (
                previous.get("generation") != expected + 1
                or previous_roles != values["roles"]
                or previous.get("status") != values["status"]
                or previous.get("updated_by") != values["actor_id"]
                or previous.get("reason") != values["reason"]
            ):
                raise core.TransitionKernelError(
                    "RBAC mutation replay diverged"
                )
            return core.KernelTransition(
                mutations=(),
                result={
                    "binding": previous,
                    "previous_binding": None,
                    "generation": current_generation,
                    "state_digest": authority["state_digest"],
                    "idempotent": True,
                },
                work_units=8,
            )
        if (
            current_generation != expected
            or authority.get("binding_table_revision")
                != authority.get(
                    "verified_binding_table_revision"
                )
        ):
            raise core.TransitionKernelError(
                "RBAC authority generation changed"
            )
        if values["actor_id"].startswith("oidc:"):
            actor = (
                previous
                if values["actor_id"] == values["subject_id"]
                else _row(
                    context.exact(
                        "rbac_role_bindings",
                        {"subject_id": values["actor_id"]},
                    )
                )
            )
            actor_roles = json.loads(str(actor.get("roles_json")))
            if (
                actor.get("status") != "active"
                or "admin" not in actor_roles
            ):
                raise core.TransitionKernelError(
                    "RBAC actor is no longer an administrator"
                )
        now_iso = _database_iso(context.database_now)
        next_generation = current_generation + 1
        binding_material, binding = _rbac_binding_material(
            values,
            generation=next_generation,
            updated_at=now_iso,
        )
        next_revision = core.require_integer(
            authority["binding_table_revision"],
            "RBAC binding table revision",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX - 1,
        ) + 1
        from catchplate import authority_rbac_currentness as rbac_currentness
        binding_mutation = core.mutation(operation=self.operation, selected=binding_selected, row=binding)
        binding_root, manifest_digest = rbac_currentness.binding_after(context, binding_mutation)
        state_material = rbac_currentness.state_material(next_generation, binding_root, manifest_digest)
        state_digest = rbac_currentness.state_digest(state_material)
        authority_after = {
            **authority,
            "generation": next_generation,
            "state_digest": state_digest,
            "binding_table_revision": next_revision,
            "verified_binding_table_revision": next_revision,
            "updated_at": now_iso,
        }
        audit_event = {
            **values["event"],
            "subject_id": values["subject_id"],
            "previous_roles": (
                []
                if previous is None
                else json.loads(str(previous["roles_json"]))
            ),
            "new_roles": values["roles"],
            "status": values["status"],
            "previous_generation": current_generation,
            "generation": next_generation,
            "state_digest": state_digest,
        }
        stage = _audit_stage(
            event_type=values["event_type"],
            entity_kind="rbac_binding",
            entity_id=values["subject_id"],
            entity_revision=next_generation,
            state_digest=binding["binding_digest"],
            previous_state_digest=None,
            actor_id=values["actor_id"],
            evidence=values["event"],
            created_at_epoch_ns=_database_epoch_ns(
                context.database_now
            ),
            created_at=now_iso,
        )
        operation_id = _operation_id(
            self.operation,
            context.request_digest,
        )
        return core.KernelTransition(
            mutations=(
                *_fresh_audit_mutations(
                    context,
                    operation_id=operation_id,
                    outbox_rows=(stage["outbox"],),
                ),
                core.mutation(
                    operation=self.operation,
                    selected=context.exact(
                        "policy_authority_transition_audits",
                        {
                            "transition_digest":
                                stage["transition"][
                                    "transition_digest"
                                ]
                        },
                    ),
                    row=stage["transition"],
                ),
                core.mutation(
                    operation=self.operation,
                    selected=binding_selected,
                    row=binding,
                ),
                core.mutation(
                    operation=self.operation,
                    selected=authority_selected,
                    row=authority_after,
                ),
            ),
            result={
                "binding": binding_material,
                "previous_binding": previous,
                "generation": next_generation,
                "state_digest": state_digest,
                "audit": stage["outbox"],
                "projection": {
                    "status": "deferred",
                    "generation": next_generation,
                },
                "idempotent": False,
            },
            work_units=72,
        )


def _activation_abort_arguments(
    arguments: Mapping[str, Any],
) -> tuple[str, str, str]:
    core.require_exact_arguments(arguments, _ACTIVATION_ABORT_FIELDS)
    preparation_digest = core.require_digest(
        arguments["preparationDigest"],
        "activation abort preparation",
    )
    reason = arguments["reason"]
    if reason not in {
        "expired",
        "predecessor_conflict",
        "approval_revoked",
        "trust_revoked",
        "operator_cancelled",
    }:
        raise core.TransitionKernelError(
            "activation abort reason is invalid"
        )
    aborted_by = core.require_text(
        arguments["abortedBy"],
        "activation abort actor",
        maximum_bytes=1024,
    )
    return preparation_digest, str(reason), aborted_by


def _activation_abort_material(
    *,
    preparation_digest: str,
    reason: str,
    aborted_by: str,
    aborted_at_epoch_ns: int,
) -> tuple[str, dict[str, Any]]:
    material = {
        "schema": "catchplate.policyActivationAbort/v2",
        "abortedAtEpochNs": aborted_at_epoch_ns,
        "abortedBy": aborted_by,
        "preparationDigest": preparation_digest,
        "reason": reason,
    }
    return (
        core.framed_digest(
            "catchplate.policyActivationAbort/v2",
            core.canonical_bytes(material),
        ),
        material,
    )


@dataclass(frozen=True, slots=True)
class _PolicyActivationAbortKernel:
    operation: str = "policy.activation.abort"
    handler: str = "catchplate_policy_authority_abort"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "policy.activation.abort",
        "catchplate_policy_authority_abort",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        core.require_digest(
            request_digest,
            "activation abort request digest",
        )
        preparation_digest, reason, aborted_by = (
            _activation_abort_arguments(arguments)
        )
        aborted_at_epoch_ns = _database_epoch_ns(database_now)
        abort_digest, _ = _activation_abort_material(
            preparation_digest=preparation_digest,
            reason=reason,
            aborted_by=aborted_by,
            aborted_at_epoch_ns=aborted_at_epoch_ns,
        )
        stage = _audit_stage(
            event_type="policy.activation.aborted",
            entity_kind="activation_abort",
            entity_id=preparation_digest,
            entity_revision=1,
            state_digest=abort_digest,
            previous_state_digest=preparation_digest,
            actor_id=aborted_by,
            evidence={
                "preparationDigest": preparation_digest,
                "reason": reason,
            },
            created_at_epoch_ns=aborted_at_epoch_ns,
            created_at=_database_iso(database_now),
        )
        sidecar_reference = core.SelectedRowFieldReference(
            table="policy_authority_activation_evidence_bindings",
            key={"preparation_digest": preparation_digest},
            column="evidence_digest",
        )
        return (
            _exact_query(
                operation=self.operation,
                name="preparation",
                table="policy_activation_preparations",
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="activation_evidence_binding",
                table=(
                    "policy_authority_activation_evidence_bindings"
                ),
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="decision_evidence",
                table="policy_authority_external_evidence_receipts",
                key={"evidence_digest": sidecar_reference},
            ),
            _exact_query(
                operation=self.operation,
                name="finalization",
                table="policy_activation_finalizations",
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="abort",
                table="policy_activation_aborts",
                key={"preparation_digest": preparation_digest},
            ),
            _exact_query(
                operation=self.operation,
                name="abort_outbox",
                table="metadata_audit_outbox",
                key={"id": stage["outbox"]["id"]},
            ),
            _exact_query(
                operation=self.operation,
                name="abort_transition",
                table="policy_authority_transition_audits",
                key={
                    "transition_digest":
                        stage["transition"]["transition_digest"]
                },
            ),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        preparation_digest, reason, aborted_by = (
            _activation_abort_arguments(context.arguments)
        )
        preparation = _row(
            context.exact(
                "policy_activation_preparations",
                {"preparation_digest": preparation_digest},
            )
        )
        sidecar_selected = context.exact(
            "policy_authority_activation_evidence_bindings",
            {"preparation_digest": preparation_digest},
        )
        sidecar = _row(sidecar_selected)
        existing_abort = context.exact(
            "policy_activation_aborts",
            {"preparation_digest": preparation_digest},
        )
        if existing_abort.get("present") is True:
            abort = _row(existing_abort)
            if (
                abort.get("abort_reason") != reason
                or abort.get("aborted_by") != aborted_by
                or sidecar.get("status") != "aborted"
                or sidecar.get("activation_attempt_id")
                    != abort.get("activation_attempt_id")
            ):
                raise core.TransitionKernelError(
                    "activation abort replay diverged"
                )
            return core.KernelTransition(
                mutations=(),
                result={
                    "ok": True,
                    "idempotent": True,
                    "status": "aborted",
                    **abort,
                },
                work_units=8,
            )
        if (
            context.exact(
                "policy_activation_finalizations",
                {"preparation_digest": preparation_digest},
            ).get("present") is True
            or sidecar.get("status") != "prepared"
            or sidecar.get("activation_attempt_id")
                != preparation.get("activation_attempt_id")
        ):
            raise core.TransitionKernelError(
                "finalized activation cannot be aborted"
            )
        evidence_digest = core.require_digest(
            sidecar["evidence_digest"],
            "activation decision-gate evidence",
        )
        _consumed_decision_gate_statement(
            context,
            evidence_digest=evidence_digest,
            consumed_operation_id=core.require_text(
                sidecar["consumed_operation_id"],
                "activation evidence consuming operation",
                maximum_bytes=256,
            ),
        )
        aborted_at_epoch_ns = _database_epoch_ns(context.database_now)
        if (
            reason == "expired"
            and aborted_at_epoch_ns
                < int(preparation["expires_at_epoch_ns"])
        ):
            raise core.TransitionKernelError(
                "activation cannot expire before its deadline"
            )
        abort_digest, _ = _activation_abort_material(
            preparation_digest=preparation_digest,
            reason=reason,
            aborted_by=aborted_by,
            aborted_at_epoch_ns=aborted_at_epoch_ns,
        )
        stage = _audit_stage(
            event_type="policy.activation.aborted",
            entity_kind="activation_abort",
            entity_id=preparation_digest,
            entity_revision=1,
            state_digest=abort_digest,
            previous_state_digest=preparation_digest,
            actor_id=aborted_by,
            evidence={
                "preparationDigest": preparation_digest,
                "reason": reason,
            },
            created_at_epoch_ns=aborted_at_epoch_ns,
            created_at=_database_iso(context.database_now),
        )
        abort = {
            "preparation_digest": preparation_digest,
            "activation_attempt_id":
                preparation["activation_attempt_id"],
            "abort_reason": reason,
            "abort_digest": abort_digest,
            "abort_transition_digest":
                stage["transition"]["transition_digest"],
            "aborted_by": aborted_by,
            "aborted_at_epoch_ns": aborted_at_epoch_ns,
        }
        sidecar_after = {
            **sidecar,
            "status": "aborted",
            "finalized_at_epoch_ns": aborted_at_epoch_ns,
        }
        mutations = (
            *_fresh_audit_mutations(
                context,
                operation_id=_operation_id(
                    self.operation,
                    context.request_digest,
                ),
                outbox_rows=(stage["outbox"],),
            ),
            core.mutation(
                operation=self.operation,
                selected=context.exact(
                    "policy_authority_transition_audits",
                    {
                        "transition_digest":
                            stage["transition"][
                                "transition_digest"
                            ]
                    },
                ),
                row=stage["transition"],
            ),
            core.mutation(
                operation=self.operation,
                selected=existing_abort,
                row=abort,
            ),
            core.mutation(
                operation=self.operation,
                selected=sidecar_selected,
                row=sidecar_after,
            ),
        )
        return core.KernelTransition(
            mutations=mutations,
            result={
                "ok": True,
                "idempotent": False,
                "status": "aborted",
                **abort,
            },
            work_units=48,
        )


def _bounded_scan_query(
    *,
    operation: str,
    name: str,
    table: str,
    predicates: Mapping[str, Any],
    order_by: tuple[str, ...],
    maximum_rows: int,
) -> core.BoundedQuery:
    return core.BoundedQuery(
        query_id=core.query_program_id(operation, name, table),
        table=table,
        predicates=tuple(
            core.QueryPredicate(column, "eq", value)
            for column, value in sorted(predicates.items())
        ),
        order_by=tuple(
            core.QueryOrder(column) for column in order_by
        ),
        maximum_rows=maximum_rows,
    )


def _canonical_object(
    value: Any,
    label: str,
    *,
    maximum_bytes: int = authority_contract.MAX_REQUEST_BYTES,
) -> tuple[dict[str, Any], str]:
    item = _mapping(value, label)
    encoded = core.canonical_bytes(item)
    if len(encoded) > maximum_bytes:
        raise core.TransitionKernelError(f"{label} exceeds its byte bound")
    return item, encoded.decode("ascii")


def _canonical_array(
    value: Any,
    label: str,
    *,
    maximum_items: int,
    maximum_bytes: int = authority_contract.MAX_REQUEST_BYTES,
) -> tuple[list[Any], str]:
    items = _list(value, label, maximum=maximum_items)
    encoded = core.canonical_bytes(items)
    if len(encoded) > maximum_bytes:
        raise core.TransitionKernelError(f"{label} exceeds its byte bound")
    return items, encoded.decode("ascii")


def _metadata_outbox_row(
    *,
    operation: str,
    request_digest: str,
    event_type: str,
    actor_id: str,
    event: Mapping[str, Any],
    created_at: str,
) -> dict[str, Any]:
    event_json = core.canonical_bytes(dict(event)).decode("ascii")
    return {
        "id": core.deterministic_uuid(
            operation=operation,
            request_digest=request_digest,
            purpose="metadata-audit-outbox",
        ),
        "event_type": event_type,
        "actor_type": "admin",
        "actor_id": actor_id,
        "event_json": event_json,
        "event_digest": core.framed_digest(
            "catchplate.metadataAuditOutboxEvent/v1",
            event_json.encode("ascii"),
        ),
        "storage_format_version": 2,
        "status": "pending",
        "claim_id": None,
        "claimed_at": None,
        "attempts": 0,
        "audited_at": None,
        "audit_event_hash": None,
        "last_error": None,
        "created_at": created_at,
    }


def _verified_outbox_statement(
    context: core.KernelContext,
    *,
    outbox_id: str,
    event_type: str,
    fields: frozenset[str],
    schema: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    selected = context.exact(
        "metadata_audit_outbox",
        {"id": outbox_id},
    )
    row = _row(selected)
    statement = _mapping_json(
        row.get("event_json"),
        f"{event_type} evidence",
    )
    event_json = core.canonical_bytes(statement).decode("ascii")
    if (
        set(statement) != fields
        or statement.get("schema") != schema
        or row.get("event_type") != event_type
        or row.get("status") != "audited"
        or row.get("audit_event_hash") is None
        or row.get("event_digest")
            != core.framed_digest(
                "catchplate.metadataAuditOutboxEvent/v1",
                event_json.encode("ascii"),
            )
    ):
        raise core.TransitionKernelError(
            f"{event_type} evidence is not durably verified"
        )
    core.require_digest(
        row.get("audit_event_hash"),
        f"{event_type} audit inclusion",
    )
    return row, statement


def _export_freeze_arguments(
    arguments: Mapping[str, Any],
) -> str:
    core.require_exact_arguments(
        arguments,
        _POLICY_EXPORT_FREEZE_FIELDS,
    )
    return core.require_text(
        arguments["activation_attempt_id"],
        "activation export attempt",
        maximum_bytes=256,
    )


def _export_id(
    activation_attempt_id: str,
    request_digest: str,
) -> str:
    return core.framed_digest(
        "catchplate.policyActivationChainExportMaterial/v2",
        activation_attempt_id.encode("utf-8"),
        request_digest.encode("ascii"),
    )


def _closed_finalized_export(
    row: Mapping[str, Any],
    activation_attempt_id: str,
) -> tuple[dict[str, Any], dict[str, Any], list[Any]]:
    identity = _mapping_json(
        row.get("identity_json"),
        "activation export identity",
    )
    manifest = _mapping_json(
        row.get("manifest_json"),
        "activation export manifest",
    )
    rows_material = _mapping_json(
        row.get("rows_json"),
        "activation export rows",
    )
    identity_json = core.canonical_bytes(identity).decode("ascii")
    manifest_json = core.canonical_bytes(manifest).decode("ascii")
    rows_json = core.canonical_bytes(rows_material).decode("ascii")
    sections = rows_material.get("sections")
    if not isinstance(sections, list):
        raise core.TransitionKernelError(
            "activation export sections are not closed"
        )
    flattened: list[Any] = []
    for section in sections:
        if not isinstance(section, Mapping):
            raise core.TransitionKernelError(
                "activation export section is invalid"
            )
        section_rows = section.get("rows")
        if not isinstance(section_rows, list):
            raise core.TransitionKernelError(
                "activation export section rows are invalid"
            )
        flattened.extend(section_rows)
        if len(flattened) > int(row.get("total_row_count", -1)):
            raise core.TransitionKernelError(
                "activation export row count diverged"
            )
    if (
        row.get("activation_attempt_id") != activation_attempt_id
        or identity.get("activationAttemptId")
            not in {None, activation_attempt_id}
        or rows_material.get("activationAttemptId")
            != activation_attempt_id
        or row.get("identity_digest")
            != core.framed_digest(
                "catchplate.policyActivationChainIdentity/v3",
                identity_json.encode("ascii"),
            )
        or row.get("manifest_root_digest")
            != core.framed_digest(
                "catchplate.policyActivationChainManifest/v1",
                manifest_json.encode("ascii"),
            )
        or row.get("rows_digest")
            != core.framed_digest(
                "catchplate.policyActivationFinalizedExportRows/v1",
                rows_json.encode("ascii"),
            )
        or manifest.get("identityDigest") != row.get("identity_digest")
        or rows_material.get("identityDigest")
            != row.get("identity_digest")
        or rows_material.get("manifestRootDigest")
            != row.get("manifest_root_digest")
        or len(flattened) != row.get("total_row_count")
        or row.get("source_revision")
            != authority_contract.SOURCE_REVISION
    ):
        raise core.TransitionKernelError(
            "finalized activation export binding diverged"
        )
    return identity, manifest, flattened


def _export_signing_records(
    issuance: Mapping[str, Any],
    pages: list[Mapping[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issuance_record = {
        "schema":
            "catchplate.policyActivationChainExportIssuanceRecord/v1",
        "exportId": issuance["export_id"],
        "exportRevision": issuance["export_revision"],
        "activationAttemptId": issuance["activation_attempt_id"],
        "canaryId": issuance["canary_id"],
        "assignmentEnvelopeDigest":
            issuance["assignment_envelope_digest"],
        "identityDigest": issuance["identity_digest"],
        "manifestRootDigest": issuance["manifest_root_digest"],
        "snapshotDigest": issuance["snapshot_digest"],
        "sectionCount": issuance["section_count"],
        "totalRowCount": issuance["total_row_count"],
        "totalCanonicalBytes": issuance["total_canonical_bytes"],
        "pageCount": issuance["page_count"],
        "pageChainRootDigest": issuance["page_chain_root_digest"],
        "sourceRevision": issuance["source_revision"],
        "preparedAtEpochNs": issuance["prepared_at_epoch_ns"],
        "expiresAtEpochNs": issuance["expires_at_epoch_ns"],
    }
    page_records = [
        {
            "schema":
                "catchplate.policyActivationChainExportPageRecord/v1",
            "exportId": page["export_id"],
            "exportRevision": page["export_revision"],
            "pageOrdinal": page["page_ordinal"],
            "pageCount": issuance["page_count"],
            "section": page["section_name"],
            "sectionPageOrdinal": page["section_page_ordinal"],
            "predecessorPageDigest":
                page["predecessor_page_digest"],
            "successorPageDigest": page["successor_page_digest"],
            "pageDigest": page["page_digest"],
            "rowsDigest": page["rows_digest"],
            "rowCount": page["row_count"],
            "canonicalBytes": page["canonical_bytes"],
            "cumulativeRowCount": page["cumulative_row_count"],
            "cumulativeRootDigest":
                page["cumulative_root_digest"],
            "sectionRootDigest": page["section_root_digest"],
            "snapshotDigest": issuance["snapshot_digest"],
            "manifestRootDigest": issuance["manifest_root_digest"],
            "expiresAtEpochNs": page["expires_at_epoch_ns"],
        }
        for page in pages
    ]
    return issuance_record, page_records


@dataclass(frozen=True, slots=True)
class _PolicyExportFreezeKernel:
    operation: str = "policy.export.freeze"
    handler: str = "prepare_policy_activation_chain_export"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "policy.export.freeze",
        "prepare_policy_activation_chain_export",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        activation_attempt_id = _export_freeze_arguments(arguments)
        export_id = _export_id(
            activation_attempt_id,
            core.require_digest(
                request_digest,
                "activation export freeze request",
            ),
        )
        return (
            _exact_query(
                operation=self.operation,
                name="finalized_export",
                table="policy_activation_finalized_exports",
                key={"activation_attempt_id": activation_attempt_id},
            ),
            _bounded_scan_query(
                operation=self.operation,
                name="issuance_for_activation",
                table="policy_activation_export_issuances",
                predicates={
                    "activation_attempt_id": activation_attempt_id
                },
                order_by=("export_id",),
                maximum_rows=1,
            ),
            _exact_query(
                operation=self.operation,
                name="issuance",
                table="policy_activation_export_issuances",
                key={"export_id": export_id},
            ),
            _exact_query(
                operation=self.operation,
                name="page",
                table="policy_activation_export_pages",
                key={"export_id": export_id, "page_ordinal": 1},
            ),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        activation_attempt_id = _export_freeze_arguments(
            context.arguments
        )
        export_id = _export_id(
            activation_attempt_id,
            context.request_digest,
        )
        source = _row(
            context.exact(
                "policy_activation_finalized_exports",
                {"activation_attempt_id": activation_attempt_id},
            )
        )
        identity, manifest, flattened = _closed_finalized_export(
            source,
            activation_attempt_id,
        )
        rows_json = core.canonical_bytes(flattened).decode("ascii")
        if len(rows_json.encode("ascii")) > authority_contract.MAX_REQUEST_BYTES:
            raise core.TransitionKernelError(
                "activation export requires more than one bounded page"
            )
        prepared_at = core.require_integer(
            source.get("finalized_at_epoch_ns"),
            "activation export finalized time",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        )
        expires_at = core.require_integer(
            identity.get("expiresAtEpochNs"),
            "activation export expiry",
            minimum=prepared_at + 1,
            maximum=_SIGNED_BIGINT_MAX,
        )
        if expires_at <= _database_epoch_ns(context.database_now):
            raise core.TransitionKernelError(
                "activation export source has expired"
            )
        canary_id = core.require_text(
            identity.get("canaryId"),
            "activation export canary",
            maximum_bytes=256,
        )
        assignment_digest = core.require_digest(
            identity.get("assignmentEnvelopeDigest"),
            "activation export assignment",
        )
        rows_digest = core.framed_digest(
            "catchplate.policyActivationChainPageRows/v1",
            rows_json.encode("ascii"),
        )
        content = {
            "schema":
                "catchplate.policyActivationChainPageContent/v1",
            "identityDigest": source["identity_digest"],
            "manifestRootDigest": source["manifest_root_digest"],
            "section": "complete_snapshot",
            "sectionPageOrdinal": 1,
            "rowsDigest": rows_digest,
            "rowCount": len(flattened),
            "canonicalBytes": len(rows_json.encode("ascii")),
            "cumulativeRowCount": len(flattened),
            "cumulativeRootDigest":
                source["row_identity_root_digest"],
            "sectionRootDigest": source["row_identity_root_digest"],
            "expiresAtEpochNs": expires_at,
        }
        content_digest = core.framed_digest(
            "catchplate.policyActivationChainPageContent/v1",
            core.canonical_bytes(content),
        )
        material = {
            **content,
            "pageOrdinal": 1,
            "pageCount": 1,
            "predecessorPageDigest": None,
            "successorPageDigest": None,
            "contentDigest": content_digest,
        }
        material_json = core.canonical_bytes(material).decode("ascii")
        page_digest = core.framed_digest(
            "catchplate.policyActivationChainExportPage/v1",
            material_json.encode("ascii"),
        )
        page_chain_root = core.framed_digest(
            "catchplate.policyActivationChainPageChainGenesis/v1",
            source["identity_digest"].encode("ascii"),
            source["manifest_root_digest"].encode("ascii"),
        )
        page_chain_root = core.framed_digest(
            "catchplate.policyActivationChainPageChainStep/v1",
            page_chain_root.encode("ascii"),
            page_digest.encode("ascii"),
        )
        issuance_material = {
            "schema":
                "catchplate.policyActivationChainExportMaterial/v2",
            "exportId": export_id,
            "exportRevision": 1,
            "activationAttemptId": activation_attempt_id,
            "canaryId": canary_id,
            "assignmentEnvelopeDigest": assignment_digest,
            "identityDigest": source["identity_digest"],
            "manifestRootDigest": source["manifest_root_digest"],
            "sectionCount": source["section_count"],
            "totalRowCount": source["total_row_count"],
            "totalCanonicalBytes": source["total_canonical_bytes"],
            "pageCount": 1,
            "pageChainRootDigest": page_chain_root,
            "sourceRevision": authority_contract.SOURCE_REVISION,
            "preparedAtEpochNs": prepared_at,
            "expiresAtEpochNs": expires_at,
        }
        snapshot = {
            **issuance_material,
            "schema": "catchplate.policyActivationChainSnapshot/v4",
            "identity": identity,
            "manifest": manifest,
        }
        snapshot_json = core.canonical_bytes(snapshot).decode("ascii")
        issuance = {
            "export_id": export_id,
            "export_revision": 1,
            "activation_attempt_id": activation_attempt_id,
            "canary_id": canary_id,
            "assignment_envelope_digest": assignment_digest,
            "identity_json": core.canonical_bytes(identity).decode(
                "ascii"
            ),
            "identity_digest": source["identity_digest"],
            "manifest_json": core.canonical_bytes(manifest).decode(
                "ascii"
            ),
            "manifest_root_digest": source["manifest_root_digest"],
            "snapshot_json": snapshot_json,
            "snapshot_digest": core.framed_digest(
                "catchplate.policyActivationChainSnapshot/v4",
                snapshot_json.encode("ascii"),
            ),
            "section_count": source["section_count"],
            "total_row_count": source["total_row_count"],
            "total_canonical_bytes": source["total_canonical_bytes"],
            "page_count": 1,
            "page_chain_root_digest": page_chain_root,
            "source_revision": authority_contract.SOURCE_REVISION,
            "prepared_at_epoch_ns": prepared_at,
            "expires_at_epoch_ns": expires_at,
        }
        page = {
            "export_id": export_id,
            "export_revision": 1,
            "page_ordinal": 1,
            "section_name": "complete_snapshot",
            "section_page_ordinal": 1,
            "predecessor_page_digest": None,
            "successor_page_digest": None,
            "page_material_json": material_json,
            "page_digest": page_digest,
            "rows_json": rows_json,
            "rows_digest": rows_digest,
            "row_count": len(flattened),
            "canonical_bytes": len(rows_json.encode("ascii")),
            "cumulative_row_count": len(flattened),
            "cumulative_root_digest":
                source["row_identity_root_digest"],
            "section_root_digest":
                source["row_identity_root_digest"],
            "expires_at_epoch_ns": expires_at,
        }
        other_issuances = [
            _row(selected)
            for selected in context.present_rows(
                "policy_activation_export_issuances"
            )
            if selected.get("key") != {"export_id": export_id}
        ]
        if any(
            item.get("activation_attempt_id")
                == activation_attempt_id
            and item.get("export_id") != export_id
            for item in other_issuances
        ):
            raise core.TransitionKernelError(
                "activation export already has another issuance"
            )
        mutations = tuple(
            mutation
            for mutation in (
                _immutable_mutation(
                    context,
                    table="policy_activation_export_issuances",
                    key={"export_id": export_id},
                    row=issuance,
                ),
                _immutable_mutation(
                    context,
                    table="policy_activation_export_pages",
                    key={"export_id": export_id, "page_ordinal": 1},
                    row=page,
                ),
            )
            if mutation is not None
        )
        if len(mutations) not in {0, 2}:
            raise core.TransitionKernelError(
                "activation export replay is incomplete"
            )
        issuance_record, page_records = _export_signing_records(
            issuance,
            [page],
        )
        return core.KernelTransition(
            mutations=mutations,
            result={
                "exportId": export_id,
                "snapshotDigest": issuance["snapshot_digest"],
                "issuanceRecord": issuance_record,
                "pageRecords": page_records,
                "idempotent": not mutations,
            },
            work_units=64,
        )


def _export_page_ordinals(
    value: Any,
    label: str,
) -> list[int]:
    raw = _list(
        value,
        label,
        maximum=_POLICY_EXPORT_MAX_PAGES,
    )
    ordinals = [
        core.require_integer(
            item,
            f"{label} ordinal",
            minimum=1,
            maximum=_POLICY_EXPORT_MAX_PAGES,
        )
        for item in raw
    ]
    if ordinals != list(range(1, len(ordinals) + 1)):
        raise core.TransitionKernelError(
            f"{label} is not a closed ordinal sequence"
        )
    return ordinals


def _export_authorize_arguments(
    arguments: Mapping[str, Any],
) -> tuple[str, int, int, list[int]]:
    core.require_exact_arguments(
        arguments,
        _POLICY_EXPORT_AUTHORIZE_FIELDS,
    )
    return (
        core.require_digest(
            arguments["export_id"],
            "activation export identity",
        ),
        core.require_integer(
            arguments["expected_authorization_revision"],
            "activation export authorization revision",
            minimum=1,
            maximum=_SIGNED_BIGINT_MAX - 1,
        ),
        core.require_integer(
            arguments["requested_expires_at_epoch_ns"],
            "activation export requested authorization expiry",
            minimum=1,
            maximum=_SIGNED_BIGINT_MAX,
        ),
        _export_page_ordinals(
            arguments["page_ordinals"],
            "activation export authorization pages",
        ),
    )


def _export_authorization_rows(
    *,
    issuance: Mapping[str, Any],
    revision: int,
    predecessor_digest: str | None,
    issuance_receipt_digest: str,
    issuance_issued_at: int,
    issuance_expires_at: int,
    page_receipts: list[Mapping[str, Any]],
    requested_expires_at: int | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    receipts_root = core.framed_digest(
        "catchplate.policyActivationExportAuthorizationReceiptsGenesis/v1",
        str(issuance["export_id"]).encode("ascii"),
        str(issuance["snapshot_digest"]).encode("ascii"),
        str(issuance["page_chain_root_digest"]).encode("ascii"),
    )
    authorized_at = issuance_issued_at
    expires_at = issuance_expires_at
    normalized: list[dict[str, Any]] = []
    for expected, receipt in enumerate(page_receipts, start=1):
        ordinal = core.require_integer(
            receipt.get("page_ordinal"),
            "activation export receipt page",
            minimum=1,
            maximum=_POLICY_EXPORT_MAX_PAGES,
        )
        digest = core.require_digest(
            receipt.get("verification_receipt_digest"),
            "activation export page verification receipt",
        )
        issued_at = core.require_integer(
            receipt.get("issued_at_epoch_ns"),
            "activation export page receipt issuance",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        )
        receipt_expires = core.require_integer(
            receipt.get("expires_at_epoch_ns"),
            "activation export page receipt expiry",
            minimum=issued_at + 1,
            maximum=_SIGNED_BIGINT_MAX,
        )
        if ordinal != expected:
            raise core.TransitionKernelError(
                "activation export receipt order diverged"
            )
        authorized_at = max(authorized_at, issued_at)
        expires_at = min(expires_at, receipt_expires)
        normalized.append(
            {
                "export_id": issuance["export_id"],
                "authorization_revision": revision,
                "page_ordinal": ordinal,
                "verification_receipt_digest": digest,
                "issued_at_epoch_ns": issued_at,
                "expires_at_epoch_ns": receipt_expires,
            }
        )
        receipts_root = core.framed_digest(
            (
                "catchplate."
                "policyActivationExportAuthorizationReceiptStep/v1"
            ),
            receipts_root.encode("ascii"),
            core.canonical_bytes(
                {
                    "pageOrdinal": ordinal,
                    "verificationReceiptDigest": digest,
                }
            ),
        )
    if requested_expires_at is not None:
        expires_at = min(expires_at, requested_expires_at)
    if expires_at <= authorized_at:
        raise core.TransitionKernelError(
            "activation export authorization is not fresh"
        )
    material = {
        "schema": "catchplate.policyActivationExportAuthorization/v1",
        "exportId": issuance["export_id"],
        "exportRevision": issuance["export_revision"],
        "authorizationRevision": revision,
        "snapshotDigest": issuance["snapshot_digest"],
        "pageChainRootDigest": issuance["page_chain_root_digest"],
        "predecessorAuthorizationDigest": predecessor_digest,
        "issuanceVerificationReceiptDigest":
            issuance_receipt_digest,
        "pageVerificationReceiptsRootDigest": receipts_root,
        "pageCount": issuance["page_count"],
        "authorizedAtEpochNs": authorized_at,
        "expiresAtEpochNs": expires_at,
        "sourceRevision": authority_contract.SOURCE_REVISION,
    }
    material_json = core.canonical_bytes(material).decode("ascii")
    authorization = {
        "export_id": issuance["export_id"],
        "authorization_revision": revision,
        "export_revision": issuance["export_revision"],
        "snapshot_digest": issuance["snapshot_digest"],
        "page_chain_root_digest": issuance["page_chain_root_digest"],
        "predecessor_authorization_digest": predecessor_digest,
        "authorization_material_json": material_json,
        "authorization_digest": core.framed_digest(
            "catchplate.policyActivationExportAuthorization/v1",
            material_json.encode("ascii"),
        ),
        "issuance_verification_receipt_digest":
            issuance_receipt_digest,
        "page_verification_receipts_root_digest": receipts_root,
        "authorized_at_epoch_ns": authorized_at,
        "expires_at_epoch_ns": expires_at,
        "source_revision": authority_contract.SOURCE_REVISION,
    }
    return authorization, normalized, {
        "export_id": issuance["export_id"],
        "authorization_revision": revision,
        "authorization_digest": authorization[
            "authorization_digest"
        ],
        "expires_at_epoch_ns": expires_at,
        "updated_at_epoch_ns": authorized_at,
    }


def _export_evidence_item(
    value: Any,
    *,
    page: bool,
) -> dict[str, Any]:
    expected = (
        _POLICY_EXPORT_PAGE_EVIDENCE_FIELDS
        if page
        else _POLICY_EXPORT_EVIDENCE_FIELDS
    )
    item = _mapping(value, "activation export evidence", fields=expected)
    for field in (
        "assignment_envelope_digest",
        "fleet_id",
        "envelope_digest",
        "payload_digest",
        "signature_digest",
        "record_binding_digest",
        "verification_receipt_digest",
    ):
        item[field] = core.require_digest(
            item[field],
            f"activation export evidence {field}",
        )
    for field in (
        "canary_id",
        "instance_id",
        "boot_id",
        "signing_key_id",
    ):
        item[field] = core.require_text(
            item[field],
            f"activation export evidence {field}",
            maximum_bytes=1024,
        )
    for field in (
        "member_ordinal",
        "membership_revision",
        "issued_at_epoch_ns",
        "expires_at_epoch_ns",
    ):
        item[field] = core.require_integer(
            item[field],
            f"activation export evidence {field}",
            minimum=1 if field in {
                "member_ordinal",
                "membership_revision",
            } else 0,
            maximum=_SIGNED_BIGINT_MAX,
        )
    if item["expires_at_epoch_ns"] <= item["issued_at_epoch_ns"]:
        raise core.TransitionKernelError(
            "activation export evidence has no validity interval"
        )
    if item["signature_algorithm"] != "Ed25519":
        raise core.TransitionKernelError(
            "activation export evidence algorithm is not pinned"
        )
    item["signature"] = core.require_text(
        item["signature"],
        "activation export evidence signature",
        maximum_bytes=4096,
    )
    for field in ("envelope_json", "payload_json"):
        parsed = json.loads(
            core.require_text(
                item[field],
                f"activation export evidence {field}",
                maximum_bytes=authority_contract.MAX_REQUEST_BYTES,
            )
        )
        if (
            core.canonical_bytes(parsed).decode("ascii")
            != item[field]
        ):
            raise core.TransitionKernelError(
                "activation export evidence JSON is not canonical"
            )
    if page:
        item["page_ordinal"] = core.require_integer(
            item["page_ordinal"],
            "activation export evidence page",
            minimum=1,
            maximum=_POLICY_EXPORT_MAX_PAGES,
        )
    return item


def _export_finalize_arguments(
    arguments: Mapping[str, Any],
) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    core.require_exact_arguments(
        arguments,
        _POLICY_EXPORT_FINALIZE_FIELDS,
    )
    export_id = core.require_digest(
        arguments["export_id"],
        "activation export identity",
    )
    issuance = _export_evidence_item(
        arguments["issuance_evidence"],
        page=False,
    )
    raw_pages = _list(
        arguments["page_evidence"],
        "activation export page evidence",
        maximum=_POLICY_EXPORT_MAX_PAGES,
    )
    pages = [
        _export_evidence_item(value, page=True)
        for value in raw_pages
    ]
    if [page["page_ordinal"] for page in pages] != list(
        range(1, len(pages) + 1)
    ):
        raise core.TransitionKernelError(
            "activation export evidence page set is not exact"
        )
    return export_id, issuance, pages


def _verified_runtime_export_evidence(
    context: core.KernelContext,
    *,
    evidence: Mapping[str, Any],
    evidence_kind: str,
    record_binding: Mapping[str, Any],
) -> dict[str, Any]:
    selected = context.exact(
        "policy_runtime_evidence_verifications",
        {
            "verification_receipt_digest":
                evidence["verification_receipt_digest"]
        },
    )
    row = _row(selected)
    domain = (
        "catchplate.policyActivationChainExportIssuance/v1"
        if evidence_kind == "activation_export_issuance"
        else "catchplate.policyActivationChainExportPage/v1"
    )
    record_binding_digest = core.framed_digest(
        "catchplate.policyRuntimeRecordBinding/v1",
        domain.encode("ascii"),
        core.canonical_bytes(dict(record_binding)),
    )
    now_ns = _database_epoch_ns(context.database_now)
    exact = {
        "evidence_kind": evidence_kind,
        "required_role": "export",
        "assignment_envelope_digest":
            evidence["assignment_envelope_digest"],
        "member_ordinal": evidence["member_ordinal"],
        "canary_id": evidence["canary_id"],
        "fleet_id": evidence["fleet_id"],
        "membership_revision": evidence["membership_revision"],
        "instance_id": evidence["instance_id"],
        "boot_id": evidence["boot_id"],
        "signing_key_id": evidence["signing_key_id"],
        "signature": evidence["signature"],
        "signature_digest": evidence["signature_digest"],
        "record_binding_digest": record_binding_digest,
        "envelope_digest": evidence["envelope_digest"],
        "payload_digest": evidence["payload_digest"],
        "issued_at_epoch_ns": evidence["issued_at_epoch_ns"],
        "expires_at_epoch_ns": evidence["expires_at_epoch_ns"],
    }
    if (
        evidence["record_binding_digest"] != record_binding_digest
        or any(row.get(field) != value for field, value in exact.items())
        or row.get("signature_domain") != domain
        or row.get("verified_at_epoch_ns") is None
        or not evidence["issued_at_epoch_ns"]
            <= row["verified_at_epoch_ns"]
            <= now_ns
            < evidence["expires_at_epoch_ns"]
        or row.get("attestation_receipt_envelope_digest") is None
    ):
        raise core.TransitionKernelError(
            "activation export verification receipt diverged"
        )
    core.require_digest(
        row["attestation_receipt_envelope_digest"],
        "activation export verifier attestation",
    )
    return row


@dataclass(frozen=True, slots=True)
class _PolicyExportFinalizeKernel:
    operation: str = "policy.export.finalize"
    handler: str = "finalize_policy_activation_chain_export"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "policy.export.finalize",
        "finalize_policy_activation_chain_export",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        core.require_digest(
            request_digest,
            "activation export finalization request",
        )
        export_id, issuance_evidence, page_evidence = (
            _export_finalize_arguments(arguments)
        )
        queries: list[core.BoundedQuery] = [
            _exact_query(
                operation=self.operation,
                name="issuance",
                table="policy_activation_export_issuances",
                key={"export_id": export_id},
            ),
            _bounded_scan_query(
                operation=self.operation,
                name="pages",
                table="policy_activation_export_pages",
                predicates={"export_id": export_id},
                order_by=("page_ordinal",),
                maximum_rows=len(page_evidence) + 1,
            ),
            _exact_query(
                operation=self.operation,
                name="issuance_verification",
                table="policy_runtime_evidence_verifications",
                key={
                    "verification_receipt_digest":
                        issuance_evidence[
                            "verification_receipt_digest"
                        ]
                },
            ),
            _exact_query(
                operation=self.operation,
                name="issuance_attestation",
                table="policy_activation_export_attestations",
                key={"export_id": export_id},
            ),
            _exact_query(
                operation=self.operation,
                name="authorization_head",
                table=(
                    "policy_activation_export_authorization_heads"
                ),
                key={"export_id": export_id},
            ),
            _exact_query(
                operation=self.operation,
                name="authorization",
                table="policy_activation_export_authorizations",
                key={
                    "export_id": export_id,
                    "authorization_revision": 1,
                },
            ),
        ]
        for item in page_evidence:
            ordinal = item["page_ordinal"]
            queries.extend(
                (
                    _exact_query(
                        operation=self.operation,
                        name=f"page_{ordinal}",
                        table="policy_activation_export_pages",
                        key={
                            "export_id": export_id,
                            "page_ordinal": ordinal,
                        },
                    ),
                    _exact_query(
                        operation=self.operation,
                        name=f"page_verification_{ordinal}",
                        table=(
                            "policy_runtime_evidence_verifications"
                        ),
                        key={
                            "verification_receipt_digest":
                                item[
                                    "verification_receipt_digest"
                                ]
                        },
                    ),
                    _exact_query(
                        operation=self.operation,
                        name=f"page_attestation_{ordinal}",
                        table=(
                            "policy_activation_export_page_attestations"
                        ),
                        key={
                            "export_id": export_id,
                            "page_ordinal": ordinal,
                        },
                    ),
                    _exact_query(
                        operation=self.operation,
                        name=f"authorization_receipt_{ordinal}",
                        table=(
                            "policy_activation_export_"
                            "authorization_receipts"
                        ),
                        key={
                            "export_id": export_id,
                            "authorization_revision": 1,
                            "page_ordinal": ordinal,
                        },
                    ),
                )
            )
        return tuple(queries)

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        export_id, issuance_evidence, page_evidence = (
            _export_finalize_arguments(context.arguments)
        )
        issuance = _row(
            context.exact(
                "policy_activation_export_issuances",
                {"export_id": export_id},
            )
        )
        selected_pages = sorted(
            (
                _row(selected)
                for selected in context.present_rows(
                    "policy_activation_export_pages"
                )
            ),
            key=lambda item: item["page_ordinal"],
        )
        if (
            issuance.get("export_id") != export_id
            or issuance.get("source_revision")
                != authority_contract.SOURCE_REVISION
            or issuance.get("page_count") != len(page_evidence)
            or len(selected_pages) != len(page_evidence)
            or [page["page_ordinal"] for page in selected_pages]
                != list(range(1, len(page_evidence) + 1))
        ):
            raise core.TransitionKernelError(
                "activation export finalization page set diverged"
            )
        issuance_record, page_records = _export_signing_records(
            issuance,
            selected_pages,
        )
        issuance_verification = _verified_runtime_export_evidence(
            context,
            evidence=issuance_evidence,
            evidence_kind="activation_export_issuance",
            record_binding=issuance_record,
        )
        if (
            issuance_evidence["assignment_envelope_digest"]
                != issuance["assignment_envelope_digest"]
            or issuance_evidence["canary_id"] != issuance["canary_id"]
        ):
            raise core.TransitionKernelError(
                "activation export issuance signer diverged"
            )
        issuer = tuple(
            issuance_evidence[field]
            for field in (
                "assignment_envelope_digest",
                "member_ordinal",
                "canary_id",
                "fleet_id",
                "membership_revision",
                "instance_id",
                "boot_id",
                "signing_key_id",
            )
        )
        issuance_attestation = {
            "export_id": export_id,
            "export_revision": issuance["export_revision"],
            "assignment_envelope_digest":
                issuance_evidence["assignment_envelope_digest"],
            "member_ordinal": issuance_evidence["member_ordinal"],
            "canary_id": issuance_evidence["canary_id"],
            "fleet_id": issuance_evidence["fleet_id"],
            "membership_revision":
                issuance_evidence["membership_revision"],
            "instance_id": issuance_evidence["instance_id"],
            "boot_id": issuance_evidence["boot_id"],
            "issuance_envelope_json":
                issuance_evidence["envelope_json"],
            "issuance_envelope_digest":
                issuance_evidence["envelope_digest"],
            "issuance_payload_json":
                issuance_evidence["payload_json"],
            "issuance_payload_digest":
                issuance_evidence["payload_digest"],
            "signature_algorithm": "Ed25519",
            "signing_key_id": issuance_evidence["signing_key_id"],
            "signature": issuance_evidence["signature"],
            "signature_digest": issuance_evidence["signature_digest"],
            "evidence_kind": "activation_export_issuance",
            "record_binding_digest":
                issuance_evidence["record_binding_digest"],
            "verification_receipt_digest":
                issuance_evidence["verification_receipt_digest"],
            "issued_at_epoch_ns":
                issuance_evidence["issued_at_epoch_ns"],
            "expires_at_epoch_ns":
                issuance_evidence["expires_at_epoch_ns"],
        }
        page_attestations: list[dict[str, Any]] = []
        page_receipts: list[dict[str, Any]] = []
        for page, item, record in zip(
            selected_pages,
            page_evidence,
            page_records,
            strict=True,
        ):
            page_issuer = tuple(
                item[field]
                for field in (
                    "assignment_envelope_digest",
                    "member_ordinal",
                    "canary_id",
                    "fleet_id",
                    "membership_revision",
                    "instance_id",
                    "boot_id",
                    "signing_key_id",
                )
            )
            if (
                page_issuer != issuer
                or page["page_ordinal"] != item["page_ordinal"]
            ):
                raise core.TransitionKernelError(
                    "activation export page signer diverged"
                )
            _verified_runtime_export_evidence(
                context,
                evidence=item,
                evidence_kind="activation_export_page",
                record_binding=record,
            )
            page_attestations.append(
                {
                    "export_id": export_id,
                    "page_ordinal": item["page_ordinal"],
                    "page_digest": page["page_digest"],
                    "assignment_envelope_digest":
                        item["assignment_envelope_digest"],
                    "member_ordinal": item["member_ordinal"],
                    "canary_id": item["canary_id"],
                    "fleet_id": item["fleet_id"],
                    "membership_revision":
                        item["membership_revision"],
                    "instance_id": item["instance_id"],
                    "boot_id": item["boot_id"],
                    "page_envelope_json": item["envelope_json"],
                    "page_envelope_digest": item["envelope_digest"],
                    "page_payload_json": item["payload_json"],
                    "page_payload_digest": item["payload_digest"],
                    "signature_algorithm": "Ed25519",
                    "signing_key_id": item["signing_key_id"],
                    "signature": item["signature"],
                    "signature_digest": item["signature_digest"],
                    "evidence_kind": "activation_export_page",
                    "record_binding_digest":
                        item["record_binding_digest"],
                    "verification_receipt_digest":
                        item["verification_receipt_digest"],
                    "issued_at_epoch_ns": item["issued_at_epoch_ns"],
                    "expires_at_epoch_ns":
                        item["expires_at_epoch_ns"],
                }
            )
            page_receipts.append(
                {
                    "page_ordinal": item["page_ordinal"],
                    "verification_receipt_digest":
                        item["verification_receipt_digest"],
                    "issued_at_epoch_ns": item["issued_at_epoch_ns"],
                    "expires_at_epoch_ns":
                        item["expires_at_epoch_ns"],
                }
            )
        authorization, receipts, head = _export_authorization_rows(
            issuance=issuance,
            revision=1,
            predecessor_digest=None,
            issuance_receipt_digest=issuance_evidence[
                "verification_receipt_digest"
            ],
            issuance_issued_at=issuance_evidence[
                "issued_at_epoch_ns"
            ],
            issuance_expires_at=issuance_evidence[
                "expires_at_epoch_ns"
            ],
            page_receipts=page_receipts,
        )
        if authorization["expires_at_epoch_ns"] <= _database_epoch_ns(
            context.database_now
        ):
            raise core.TransitionKernelError(
                "activation export finalization evidence expired"
            )
        mutations: list[dict[str, Any]] = []
        candidates = [
            (
                "policy_activation_export_attestations",
                {"export_id": export_id},
                issuance_attestation,
            ),
            *[
                (
                    "policy_activation_export_page_attestations",
                    {
                        "export_id": export_id,
                        "page_ordinal": row["page_ordinal"],
                    },
                    row,
                )
                for row in page_attestations
            ],
            (
                "policy_activation_export_authorizations",
                {
                    "export_id": export_id,
                    "authorization_revision": 1,
                },
                authorization,
            ),
            *[
                (
                    "policy_activation_export_authorization_receipts",
                    {
                        "export_id": export_id,
                        "authorization_revision": 1,
                        "page_ordinal": row["page_ordinal"],
                    },
                    row,
                )
                for row in receipts
            ],
            (
                "policy_activation_export_authorization_heads",
                {"export_id": export_id},
                head,
            ),
        ]
        replay_count = 0
        for table, key, row in candidates:
            mutation = _immutable_mutation(
                context,
                table=table,
                key=key,
                row=row,
            )
            if mutation is None:
                replay_count += 1
            else:
                mutations.append(mutation)
        if replay_count not in {0, len(candidates)}:
            raise core.TransitionKernelError(
                "activation export finalization replay is incomplete"
            )
        del issuance_verification
        return core.KernelTransition(
            mutations=tuple(mutations),
            result={
                "exportId": export_id,
                "snapshotDigest": issuance["snapshot_digest"],
                "issuanceEnvelopeDigest":
                    issuance_evidence["envelope_digest"],
                "pageCount": issuance["page_count"],
                "pageChainRootDigest":
                    issuance["page_chain_root_digest"],
                "authorizationRevision": 1,
                "authorizationDigest":
                    authorization["authorization_digest"],
                "authorizationExpiresAtEpochNs":
                    authorization["expires_at_epoch_ns"],
                "idempotent": not mutations,
            },
            work_units=96 + len(page_evidence) * 12,
        )


@dataclass(frozen=True, slots=True)
class _PolicyExportAuthorizeKernel:
    operation: str = "policy.export.authorize"
    handler: str = "authorize_policy_activation_chain_export"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "policy.export.authorize",
        "authorize_policy_activation_chain_export",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        core.require_digest(
            request_digest,
            "activation export authorization request",
        )
        export_id, expected, _, ordinals = (
            _export_authorize_arguments(arguments)
        )
        target = expected + 1
        queries: list[core.BoundedQuery] = [
            _exact_query(
                operation=self.operation,
                name="issuance",
                table="policy_activation_export_issuances",
                key={"export_id": export_id},
            ),
            _exact_query(
                operation=self.operation,
                name="issuance_attestation",
                table="policy_activation_export_attestations",
                key={"export_id": export_id},
            ),
            _exact_query(
                operation=self.operation,
                name="head",
                table=(
                    "policy_activation_export_authorization_heads"
                ),
                key={"export_id": export_id},
            ),
            _exact_query(
                operation=self.operation,
                name="predecessor",
                table="policy_activation_export_authorizations",
                key={
                    "export_id": export_id,
                    "authorization_revision": expected,
                },
            ),
            _exact_query(
                operation=self.operation,
                name="target",
                table="policy_activation_export_authorizations",
                key={
                    "export_id": export_id,
                    "authorization_revision": target,
                },
            ),
        ]
        for ordinal in ordinals:
            queries.extend(
                (
                    _exact_query(
                        operation=self.operation,
                        name=f"page_attestation_{ordinal}",
                        table=(
                            "policy_activation_export_page_attestations"
                        ),
                        key={
                            "export_id": export_id,
                            "page_ordinal": ordinal,
                        },
                    ),
                    _exact_query(
                        operation=self.operation,
                        name=f"target_receipt_{ordinal}",
                        table=(
                            "policy_activation_export_"
                            "authorization_receipts"
                        ),
                        key={
                            "export_id": export_id,
                            "authorization_revision": target,
                            "page_ordinal": ordinal,
                        },
                    ),
                )
            )
        return tuple(queries)

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        export_id, expected, requested_expiry, ordinals = (
            _export_authorize_arguments(context.arguments)
        )
        target = expected + 1
        issuance = _row(
            context.exact(
                "policy_activation_export_issuances",
                {"export_id": export_id},
            )
        )
        issuance_attestation = _row(
            context.exact(
                "policy_activation_export_attestations",
                {"export_id": export_id},
            )
        )
        head_selected = context.exact(
            "policy_activation_export_authorization_heads",
            {"export_id": export_id},
        )
        head = _row(head_selected)
        predecessor = _row(
            context.exact(
                "policy_activation_export_authorizations",
                {
                    "export_id": export_id,
                    "authorization_revision": expected,
                },
            )
        )
        page_attestations = [
            _row(
                context.exact(
                    "policy_activation_export_page_attestations",
                    {
                        "export_id": export_id,
                        "page_ordinal": ordinal,
                    },
                )
            )
            for ordinal in ordinals
        ]
        if (
            issuance.get("page_count") != len(ordinals)
            or head.get("authorization_revision")
                not in {expected, target}
            or predecessor.get("authorization_digest")
                != (
                    head.get("authorization_digest")
                    if head.get("authorization_revision") == expected
                    else predecessor.get("authorization_digest")
                )
            or any(
                row.get("page_ordinal") != ordinal
                for row, ordinal in zip(
                    page_attestations,
                    ordinals,
                    strict=True,
                )
            )
        ):
            raise core.TransitionKernelError(
                "activation export authorization predecessor diverged"
            )
        page_receipts = [
            {
                "page_ordinal": row["page_ordinal"],
                "verification_receipt_digest":
                    row["verification_receipt_digest"],
                "issued_at_epoch_ns": row["issued_at_epoch_ns"],
                "expires_at_epoch_ns": row["expires_at_epoch_ns"],
            }
            for row in page_attestations
        ]
        authorization, receipts, next_head = (
            _export_authorization_rows(
                issuance=issuance,
                revision=target,
                predecessor_digest=predecessor[
                    "authorization_digest"
                ],
                issuance_receipt_digest=issuance_attestation[
                    "verification_receipt_digest"
                ],
                issuance_issued_at=issuance_attestation[
                    "issued_at_epoch_ns"
                ],
                issuance_expires_at=issuance_attestation[
                    "expires_at_epoch_ns"
                ],
                page_receipts=page_receipts,
                requested_expires_at=requested_expiry,
            )
        )
        now_ns = _database_epoch_ns(context.database_now)
        if (
            requested_expiry <= now_ns
            or authorization["expires_at_epoch_ns"] <= now_ns
        ):
            raise core.TransitionKernelError(
                "activation export authorization has expired"
            )
        target_selected = context.exact(
            "policy_activation_export_authorizations",
            {
                "export_id": export_id,
                "authorization_revision": target,
            },
        )
        target_mutation = _immutable_mutation(
            context,
            table="policy_activation_export_authorizations",
            key={
                "export_id": export_id,
                "authorization_revision": target,
            },
            row=authorization,
        )
        receipt_mutations: list[dict[str, Any]] = []
        replay_receipts = 0
        for receipt in receipts:
            mutation = _immutable_mutation(
                context,
                table=(
                    "policy_activation_export_authorization_receipts"
                ),
                key={
                    "export_id": export_id,
                    "authorization_revision": target,
                    "page_ordinal": receipt["page_ordinal"],
                },
                row=receipt,
            )
            if mutation is None:
                replay_receipts += 1
            else:
                receipt_mutations.append(mutation)
        replay = target_mutation is None
        if replay != (replay_receipts == len(receipts)):
            raise core.TransitionKernelError(
                "activation export authorization replay is incomplete"
            )
        if replay:
            if _row(target_selected) != authorization or head != next_head:
                raise core.TransitionKernelError(
                    "activation export authorization replay diverged"
                )
            return core.KernelTransition(
                mutations=(),
                result={
                    **authorization,
                    "idempotent": True,
                },
                work_units=32 + len(receipts) * 4,
            )
        if head.get("authorization_revision") != expected:
            raise core.TransitionKernelError(
                "activation export authorization head advanced"
            )
        return core.KernelTransition(
            mutations=(
                target_mutation,
                *receipt_mutations,
                core.mutation(
                    operation=self.operation,
                    selected=head_selected,
                    row=next_head,
                ),
            ),
            result={
                **authorization,
                "idempotent": False,
            },
            work_units=48 + len(receipts) * 6,
        )


def _webauthn_credential_arguments(
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    core.require_exact_arguments(
        arguments,
        _WEBAUTHN_CREDENTIAL_INPUT_FIELDS,
    )
    if arguments["dev_private_key_pem"] is not None:
        raise core.TransitionKernelError(
            "plaintext WebAuthn development private keys are forbidden"
        )
    path = _list(
        arguments["attestation_trust_path"] or [],
        "WebAuthn attestation trust path",
        maximum=32,
    )
    transports = _list(
        arguments["transports"] or [],
        "WebAuthn transports",
        maximum=16,
    )
    for item in path + transports:
        core.require_text(
            item,
            "WebAuthn bounded list value",
            maximum_bytes=2048,
        )
    values = {
        "credential_id": core.require_text(
            arguments["credential_id"],
            "WebAuthn credential identity",
            maximum_bytes=4096,
        ),
        "user_id": core.require_text(
            arguments["user_id"],
            "WebAuthn user identity",
            maximum_bytes=1024,
        ),
        "label": core.require_text(
            arguments["label"],
            "WebAuthn credential label",
            maximum_bytes=1024,
        ),
        "public_key_cose": core.require_text(
            arguments["public_key_cose"],
            "WebAuthn public key",
            maximum_bytes=4 * 1024 * 1024,
        ),
        "sign_count": core.require_integer(
            arguments["sign_count"],
            "WebAuthn sign count",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        ),
        "aaguid": arguments["aaguid"],
        "authenticator_class": core.require_text(
            arguments["authenticator_class"],
            "WebAuthn authenticator class",
            maximum_bytes=128,
        ),
        "attestation_fmt": arguments["attestation_fmt"],
        "attestation_trusted": arguments["attestation_trusted"],
        "attestation_trust_path": path,
        "attestation_leaf_sha256":
            arguments["attestation_leaf_sha256"],
        "attestation_root_sha256":
            arguments["attestation_root_sha256"],
        "attestation_trust_bundle_digest":
            arguments["attestation_trust_bundle_digest"],
        "attestation_trust_bundle_sequence":
            arguments["attestation_trust_bundle_sequence"],
        "attestation_verified_at":
            arguments["attestation_verified_at"],
        "transports": transports,
        "dev_private_key_pem": None,
    }
    if not isinstance(values["attestation_trusted"], bool):
        raise core.TransitionKernelError(
            "WebAuthn attestation trust flag is invalid"
        )
    for field in (
        "aaguid",
        "attestation_fmt",
        "attestation_verified_at",
    ):
        if values[field] is not None:
            values[field] = core.require_text(
                values[field],
                f"WebAuthn {field}",
                maximum_bytes=2048,
            )
    for field in (
        "attestation_leaf_sha256",
        "attestation_root_sha256",
        "attestation_trust_bundle_digest",
    ):
        if values[field] is not None:
            values[field] = core.require_digest(
                values[field],
                f"WebAuthn {field}",
            )
    sequence = values["attestation_trust_bundle_sequence"]
    if sequence is not None:
        values["attestation_trust_bundle_sequence"] = (
            core.require_integer(
                sequence,
                "WebAuthn trust bundle sequence",
                minimum=1,
                maximum=_SIGNED_BIGINT_MAX,
            )
        )
    if (
        values["attestation_trusted"]
        and (
            values["attestation_trust_bundle_digest"] is None
            or values["attestation_trust_bundle_sequence"] is None
            or values["attestation_verified_at"] is None
        )
    ):
        raise core.TransitionKernelError(
            "trusted WebAuthn attestation lacks its trust binding"
        )
    return values


@dataclass(frozen=True, slots=True)
class _WebAuthnCredentialCreateKernel:
    operation: str = "webauthn.registration.create"
    handler: str = "create_webauthn_credential"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "webauthn.registration.create",
        "create_webauthn_credential",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        _webauthn_credential_arguments(arguments)
        record_id = core.deterministic_uuid(
            operation=self.operation,
            request_digest=request_digest,
            purpose="credential-record",
        )
        return (
            _exact_query(
                operation=self.operation,
                name="credential",
                table="webauthn_credentials",
                key={"id": record_id},
            ),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        values = _webauthn_credential_arguments(context.arguments)
        record_id = core.deterministic_uuid(
            operation=self.operation,
            request_digest=context.request_digest,
            purpose="credential-record",
        )
        selected = context.exact(
            "webauthn_credentials",
            {"id": record_id},
        )
        if selected.get("present") is True:
            stored = _row(selected)
            exact = {
                "credential_id": values["credential_id"],
                "user_id": values["user_id"],
                "label": values["label"],
                "public_key_cose": values["public_key_cose"],
                "sign_count": values["sign_count"],
                "aaguid": values["aaguid"],
                "authenticator_class":
                    values["authenticator_class"],
                "attestation_fmt": values["attestation_fmt"],
                "attestation_trusted":
                    1 if values["attestation_trusted"] else 0,
                "attestation_trust_path":
                    core.canonical_bytes(
                        values["attestation_trust_path"]
                    ).decode("ascii"),
                "attestation_leaf_sha256":
                    values["attestation_leaf_sha256"],
                "attestation_root_sha256":
                    values["attestation_root_sha256"],
                "attestation_trust_bundle_digest":
                    values["attestation_trust_bundle_digest"],
                "attestation_trust_bundle_sequence":
                    values["attestation_trust_bundle_sequence"],
                "attestation_verified_at":
                    values["attestation_verified_at"],
                "transports": core.canonical_bytes(
                    values["transports"]
                ).decode("ascii"),
                "dev_private_key_pem": None,
            }
            if any(stored.get(field) != value for field, value in exact.items()):
                raise core.TransitionKernelError(
                    "WebAuthn credential creation replay diverged"
                )
            return core.KernelTransition(
                mutations=(),
                result=stored,
                work_units=4,
            )
        now_iso = _database_iso(context.database_now)
        row = {
            "id": record_id,
            "credential_id": values["credential_id"],
            "user_id": values["user_id"],
            "label": values["label"],
            "public_key_cose": values["public_key_cose"],
            "sign_count": values["sign_count"],
            "aaguid": values["aaguid"],
            "authenticator_class": values["authenticator_class"],
            "attestation_fmt": values["attestation_fmt"],
            "attestation_trusted":
                1 if values["attestation_trusted"] else 0,
            "attestation_trust_path": core.canonical_bytes(
                values["attestation_trust_path"]
            ).decode("ascii"),
            "attestation_leaf_sha256":
                values["attestation_leaf_sha256"],
            "attestation_root_sha256":
                values["attestation_root_sha256"],
            "attestation_trust_bundle_digest":
                values["attestation_trust_bundle_digest"],
            "attestation_trust_bundle_sequence":
                values["attestation_trust_bundle_sequence"],
            "attestation_verified_at":
                values["attestation_verified_at"],
            "transports": core.canonical_bytes(
                values["transports"]
            ).decode("ascii"),
            "dev_private_key_pem": None,
            "created_at": now_iso,
            "updated_at": now_iso,
            "last_used_at": None,
            "revoked_at": None,
            "revoked_by": None,
            "revocation_reason": None,
            "revocation_source": None,
        }
        return core.KernelTransition(
            mutations=(
                core.mutation(
                    operation=self.operation,
                    selected=selected,
                    row=row,
                ),
            ),
            result=row,
            work_units=12,
        )


def _webauthn_counter_arguments(
    arguments: Mapping[str, Any],
) -> tuple[str, str, int, int]:
    core.require_exact_arguments(arguments, _WEBAUTHN_COUNTER_FIELDS)
    return (
        core.require_text(
            arguments["recordId"],
            "WebAuthn credential record identity",
            maximum_bytes=256,
        ),
        core.require_text(
            arguments["credentialId"],
            "WebAuthn credential identity",
            maximum_bytes=4096,
        ),
        core.require_integer(
            arguments["expectedSignCount"],
            "WebAuthn expected sign count",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        ),
        core.require_integer(
            arguments["newSignCount"],
            "WebAuthn new sign count",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        ),
    )


@dataclass(frozen=True, slots=True)
class _WebAuthnCounterCasKernel:
    operation: str = "webauthn.counter.cas"
    handler: str = "compare_and_swap_webauthn_sign_count"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "webauthn.counter.cas",
        "compare_and_swap_webauthn_sign_count",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        core.require_digest(request_digest, "WebAuthn counter request")
        record_id, _, _, _ = _webauthn_counter_arguments(arguments)
        return (
            _exact_query(
                operation=self.operation,
                name="credential",
                table="webauthn_credentials",
                key={"id": record_id},
            ),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        (
            record_id,
            credential_id,
            expected_count,
            new_count,
        ) = _webauthn_counter_arguments(context.arguments)
        selected = context.exact(
            "webauthn_credentials",
            {"id": record_id},
        )
        valid_transition = (
            expected_count == 0 and new_count == 0
        ) or new_count > expected_count
        if (
            selected.get("present") is not True
            or not valid_transition
        ):
            return core.KernelTransition(
                mutations=(),
                result=False,
                work_units=2,
            )
        row = _row(selected)
        if (
            row.get("credential_id") != credential_id
            or row.get("revoked_at") is not None
        ):
            return core.KernelTransition(
                mutations=(),
                result=False,
                work_units=2,
            )
        current = core.require_integer(
            row.get("sign_count"),
            "stored WebAuthn sign count",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        )
        if current == new_count:
            return core.KernelTransition(
                mutations=(),
                result=True,
                work_units=2,
            )
        if current != expected_count:
            return core.KernelTransition(
                mutations=(),
                result=False,
                work_units=2,
            )
        now_iso = _database_iso(context.database_now)
        return core.KernelTransition(
            mutations=(
                core.mutation(
                    operation=self.operation,
                    selected=selected,
                    row={
                        **row,
                        "sign_count": new_count,
                        "last_used_at": now_iso,
                        "updated_at": now_iso,
                    },
                ),
            ),
            result=True,
            work_units=8,
        )


@dataclass(frozen=True, slots=True)
class _TrustPublicationErrorKernel:
    operation: str = "webauthn.trust.error"
    handler: str = "record_webauthn_trust_publication_error"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "webauthn.trust.error",
        "record_webauthn_trust_publication_error",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        core.require_digest(
            request_digest,
            "WebAuthn trust error request digest",
        )
        core.require_exact_arguments(arguments, _TRUST_ERROR_FIELDS)
        publication_id = _bounded_string(
            arguments["publication_id"],
            "WebAuthn trust publication ID",
            maximum_bytes=authority_contract.MAX_REQUEST_BYTES,
        )
        return (
            core.BoundedQuery(
                query_id=core.query_program_id(
                    self.operation,
                    "publication",
                    "webauthn_trust_publications",
                ),
                table="webauthn_trust_publications",
                predicates=(
                    core.QueryPredicate("id", "eq", publication_id),
                ),
                order_by=(core.QueryOrder("id"),),
                maximum_rows=1,
                absent_key={"id": publication_id},
            ),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        core.require_exact_arguments(context.arguments, _TRUST_ERROR_FIELDS)
        publication_id = _bounded_string(
            context.arguments["publication_id"],
            "WebAuthn trust publication ID",
            maximum_bytes=authority_contract.MAX_REQUEST_BYTES,
        )
        error = str(context.arguments["error"])
        selected = context.exact(
            "webauthn_trust_publications",
            {"id": publication_id},
        )
        if selected.get("present") is not True:
            return core.KernelTransition(mutations=(), result=None)
        row = _row(selected)
        attempts = row.get("attempts")
        if (
            not isinstance(attempts, int)
            or isinstance(attempts, bool)
            or attempts < 0
            or attempts >= _SIGNED_BIGINT_MAX
        ):
            raise core.TransitionKernelError(
                "WebAuthn trust publication attempt count is invalid"
            )
        if row.get("status") != "pending":
            return core.KernelTransition(mutations=(), result=None)
        updated = {
            **row,
            "attempts": attempts + 1,
            "last_error": error[:2048],
        }
        return core.KernelTransition(
            mutations=(
                core.mutation(
                    operation=self.operation,
                    selected=selected,
                    row=updated,
                ),
            ),
            result=None,
        )


_KERNEL_VALUES: tuple[core.TransitionKernel, ...] = (
    _PolicyActivationPrepareKernel(),
    _PolicyActivationRecordInclusionKernel(),
    _PolicyActivationFinalizeKernel(),
    _PolicyActivationAbortKernel(),
    _PolicyGenesisPrepareKernel(),
    _PolicyGenesisFinalizeKernel(),
    _PolicyExportFreezeKernel(),
    _PolicyExportAuthorizeKernel(),
    _PolicyExportFinalizeKernel(),
    _RbacBindingMutateKernel(),
    _WebAuthnCredentialCreateKernel(),
    _WebAuthnCounterCasKernel(),
    _TrustPublicationErrorKernel(),
)

KERNELS: Mapping[str, core.TransitionKernel] = MappingProxyType(
    {kernel.operation: kernel for kernel in _KERNEL_VALUES}
)

_REQUESTED_OPERATIONS = frozenset(
    {
        "policy.activation.prepare",
        "policy.activation.record-inclusion",
        "policy.activation.finalize",
        "policy.activation.abort",
        "policy.genesis.prepare",
        "policy.genesis.finalize",
        "policy.export.freeze",
        "policy.export.authorize",
        "policy.export.finalize",
        "rbac.binding.mutate",
        "webauthn.trust.error",
        "webauthn.registration.create",
        "webauthn.counter.cas",
    }
)

if (
    set(KERNELS) != _REQUESTED_OPERATIONS
    or any(
        authority_contract.operation_spec(operation)["handler"]
        != kernel.handler
        or authority_contract.transition_program_id(operation)
        != kernel.program_id
        for operation, kernel in KERNELS.items()
    )
):
    raise RuntimeError("policy authority transition registry is not closed")
