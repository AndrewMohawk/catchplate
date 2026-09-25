from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from serverware import authority_complete_query
from serverware.authority_query_read_work import _ValidationWork


SOURCE_REVISION = "serverware.policyCandidateAuthoritySource/2026-07-30.141"
SCHEMA_VERSION = 9
CONTRACT_SCHEMA = "serverware.policyAuthorityOperationContract/v3"
BUSINESS_INTENT_SCHEMA = "serverware.policyAuthorityBusinessIntent/v2"
REQUEST_SCHEMA = "serverware.policyAuthorityRuntimeRequest/v2"
RESULT_SCHEMA = "serverware.policyAuthorityRuntimeResponse/v2"
CAPABILITY_SCHEMA = "serverware.policyAuthorityDatabaseCapability/v3"
INTERNAL_ENVELOPE_SCHEMA = "serverware.policyAuthorityInternalEnvelope/v3"
WITNESS_SCHEMA = "serverware.policyAuthorityReplayWitnessReceipt/v2"
MIGRATION_RECEIPT_SCHEMA = (
    "serverware.policyCandidateAuthorityOfflineMigrationReceipt/v2"
)
MIGRATION_RECEIPT_DIGEST_DOMAIN = (
    "serverware.policyCandidateAuthorityOfflineReceipt/v2"
)
MIGRATION_RECEIPT_SIGNATURE_DOMAIN = (
    "serverware.policyCandidateAuthorityOfflineMigrationReceiptSignature/v2"
)
MIGRATION_SIGNER_IDENTITY_DOMAIN = (
    "serverware.policyCandidateAuthorityOfflineMigrationSigner/v1"
)
MIGRATION_MANIFEST_DIGEST_DOMAIN = (
    "serverware.policyCandidateAuthorityMigrationManifest/v1"
)
MIGRATION_ROWS_DIGEST_DOMAIN = (
    "serverware.policyCandidateAuthorityMigrationRows/v1"
)
V8_TO_V9_MIGRATION_CONTRACT_ID = (
    "serverware.policyCandidateAuthorityOfflineMigration/v2:v8-to-v9"
)
V8_TO_V9_MIGRATION_NAME = "policy-candidate-authority-v8-to-v9"
V8_TO_V9_MIGRATION_RECEIPT_HANDLER = (
    "record_policy_candidate_authority_v8_to_v9_receipt"
)
TREE_DEPTH = 64
TREE_RADIX = 16
MAX_QUERY_PROOFS = 256
MAX_SELECTORS_PER_OPERATION = 128
MAX_PROOF_NODES = TREE_DEPTH * MAX_SELECTORS_PER_OPERATION * (TREE_RADIX - 1)
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RESULT_BYTES = 64 * 1024 * 1024
# Shared source policy; the database verifier keeps aliases to these exact
# existing values. Revocation issuer construction may tighten the age using
# measured internal policy, but never derives either bound from a request.
VERIFIER_RESPONSE_MAX_AGE_NS = 30 * 1_000_000_000
VERIFIER_MAX_CLOCK_SKEW_NS = 5 * 1_000_000_000
MAX_MUTATIONS = 512
MAX_WORK_UNITS = 16384
# Original business bounds above remain unchanged. Only the exact framework
# global-audit row/mutation may use these named final-plan allowances.
AUDIT_CAPACITY_QUERY_WORK_UNITS = 1
AUDIT_CAPACITY_MUTATION_WORK_UNITS = 1
MAX_PLAN_QUERY_ROWS = MAX_QUERY_PROOFS + 1
MAX_PLAN_MUTATIONS = MAX_MUTATIONS + 1
MAX_PLAN_WORK_UNITS = MAX_WORK_UNITS + 2
MAX_PLAN_SELECTED_BYTES = MAX_REQUEST_BYTES + 8192
# One cumulative ledger for actual typed-query observation bookkeeping. This
# admission is separate from signed business workUnits and the staging proof
# and cache-stamp budgets; it is not a whole-planner resource contract.
PLANNER_QUERY_BOOKKEEPING_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthorityPlannerQueryBookkeeping/v1",
    "allocation": "once-per-typed-derive",
    "maxHashes": 8_000_000,
    "maxInputBytes": 64 * 1024 * 1024,
    "maxJsonNodes": 1_000_000,
    "maxJsonDepth": 128,
    "includedPhases": (
        "snapshot", "reference-sources", "resolve", "capture", "prefix-budget",
        "end-of-read-validation", "post-primary-validation",
    ),
    "excludedWork": (
        "sql-acquisition", "primary-proof-verification", "staging-cache-stamps",
        "kernel", "range-and-mutation-proofs", "whole-plan",
    ),
})
# This private acquisition worker shares the caller's existing work object;
# it does not extend public v3 transport, registry or root/time authority.
# Literal profile names avoid importing head/reader/trace modules back into
# their own contract dependency. Source fixtures pin them to the real modules.
PLANNER_COMPLETE_ACQUISITION_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthorityPlannerCompleteAcquisition/v1",
    "admission": "private-worker-only",
    "publicV3Enabled": False,
    "operation": "webauthn.credential.revoke",
    "producerReadPhase": "single-cutoff-source-program/v1",
    "producerAcquisitionPhase": "single-ledger-read-effects-write/v1",
    "retainedPrimaryEvidence": "detached-original-roots-and-proofs/v1",
    "headTraceProfile": "serverware.policyAuthorityCountedHeadRead/v1",
    "rangeTraceProfile": "serverware.policyAuthorityCountedIndexRead/v1",
    "primaryTraceProfile": "serverware.policyAuthorityCompletePrimaryRead/v1",
    "mutationTraceProfile": "serverware.policyAuthorityCountedIndexMutationRead/v1",
    "maxSqlReads": 4096,
    "maxParameterBytes": 4 * 1024 * 1024,
    "maxReturnedFrameBytes": 4 * 1024 * 1024,
    "maxPrimaryRowBytes": 1024 * 1024,
    "maxRangeSqlReads": 20,
    "maxSharedHashes": 8_000_000,
    "maxSharedInputBytes": 64 * 1024 * 1024,
    "maxSharedJsonNodes": 1_000_000,
    "maxBusinessTraceEntries": 4096,
    "maxFrameworkTraceEntries": 69,
    "includedPhases": (
        "owned-producer-context", "request-and-operation-binding",
        "assertion-receipt-verification",
        "owned-read-phase-context", "single-cutoff-source-query-generation",
        "source-role-and-cutoff-binding", "counted-head-capture",
        "range-acquisition-and-reconstruction", "exact-primary-row-fetch",
        "raw-evidence-retention", "global-primary-and-range-row-reverification",
        "shared-query-bookkeeping", "detached-root-and-primary-proof-retention",
        "actual-kernel-and-capacity-effects", "ordered-mutation-copy",
        "write-frontier-acquisition", "indexed-primary-and-sparse-write-proofs",
        "shared-physical-acquisition",
    ),
    "excludedWork": (
        "sql-execution", "driver-allocation", "process-allocation",
        "staged-proof-work", "staging-cache-stamps", "primary-proof-acquisition",
        "trace-serialization", "fixed-metadata-scaffolding", "indexed-projection-allocation",
        "retained-protocol", "whole-plan",
    ),
})
# This successor verifier is source-bound but not a production transport or
# persistence admission. Literal schemas keep this module below its consumers.
SIGNED_REVOCATION_PLAN_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthoritySignedRevocationPlanVerification/v1",
    "admission": "private-verifier-only",
    "operation": "webauthn.credential.revoke",
    "publicV3Enabled": False,
    "productionV4Enabled": False,
    "responseSchema": "serverware.policyAuthorityPlannerResponse/v4",
    "measuredPlanSchema": "serverware.policyAuthorityMeasuredPlan/v4",
    "signedPlanSchema": "serverware.signedPolicyAuthorityMeasuredPlan/v4",
    "snapshotDomain": "serverware.policyAuthoritySnapshot/v4",
    "writerTraceBinding": "exact-contiguous-source-batches-before-writes/v1",
    "maxPayloadBytes": 64 * 1024 * 1024,
    "maxSharedHashes": 8_000_000,
    "maxSharedInputBytes": 64 * 1024 * 1024,
    "maxSharedJsonNodes": 1_000_000,
    "maxJsonDepth": 128,
    "includedPhases": (
        "joint-envelope-and-expectation-capture", "full-transport-encoding",
        "planner-signature", "assertion-receipt-signature", "source-query-closure",
        "primary-and-complete-range-proofs", "actual-kernel-and-capacity-effects",
        "authorization-source-binding", "snapshot-and-result-commitments",
        "source-bound-trace-consistency",
        "mutation-writer-target-geometry", "exact-mutation-writer-trace",
    ),
    "excludedWork": (
        "indexed-projection-allocation", "fixed-metadata-scaffolding", "whole-plan",
    ),
    "excludedAuthority": (
        "key-and-identity-enrollment", "before-root-and-cutoff-currentness",
        "capability-reservation", "one-use-persistence", "sql-commit",
        "registry-admission", "terminal-witness",
    ),
})
# Private production of an original signed envelope is distinct from public
# protocol activation, persisted replay or independently enrolled authority.
SIGNED_REVOCATION_PRODUCTION_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthoritySignedRevocationPlanProduction/v1",
    "admission": "private-producer-only",
    "operation": "webauthn.credential.revoke",
    "publicV3Enabled": False,
    "productionV4Enabled": False,
    "proofPackaging": "genuine-mixed-replay-on-original-work/v1",
    "transportReservation": "measured-payload-and-envelope-before-signing/v1",
    "contextSchema": "serverware.policyAuthorityRevocationEvaluationContext/v1",
    "maxContextBytes": 512 * 1024,
    "maxContextNodes": 4096,
    "maxContextDepth": 8,
    "maxPayloadBytes": 64 * 1024 * 1024,
    "maxSharedHashes": 8_000_000,
    "maxSharedInputBytes": 64 * 1024 * 1024,
    "maxSharedJsonNodes": 1_000_000,
    "maxJsonDepth": 128,
    "includedPhases": (
        "joint-request-evidence-context-capture", "reservation-context-binding",
        "actual-root-read-binding",
        "single-cutoff-read-effects-write-acquisition", "independent-before-vector-binding",
        "raw-proof-normalization", "genuine-mixed-proof-replay", "compact-proof-packaging",
        "original-evaluation-context-encoding",
        "source-authorization-and-plan-commitments", "exact-outer-transport-preflight",
        "planner-signature", "paired-public-key-verification",
        "post-sign-payload-and-meter-stability", "original-envelope-encoding",
    ),
    "excludedWork": (
        "sql-execution", "driver-allocation", "process-allocation",
        "staged-proof-work", "staging-cache-stamps", "primary-proof-acquisition",
        "acquisition-trace-serialization", "indexed-projection-allocation",
        "fixed-metadata-scaffolding", "whole-plan",
    ),
    "excludedAuthority": (
        "key-and-identity-enrollment", "read-only-transaction-ownership",
        "before-root-and-cutoff-currentness", "capability-reservation",
        "one-use-persistence", "sql-commit", "registry-admission", "terminal-witness",
    ),
})
# Original-byte admission is a private verification boundary, not a storage
# protocol or permission to execute a historically valid plan.
SIGNED_REVOCATION_WIRE_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthoritySignedRevocationWireAdmission/v1",
    "admission": "private-wire-verifier-only",
    "operation": "webauthn.credential.revoke",
    "publicV3Enabled": False,
    "productionV4Enabled": False,
    "inputEncoding": "canonical-ascii-json/v1",
    "workOwnership": "existing-invocation-remaining-allowance/v1",
    "decoderByteReservation": "four-times-original-byte-count/v1",
    "decoderNodeReservation": "tokens-plus-objects-plus-two-members/v1",
    "canonicalComparison": "actual-transport-encoder-before-signature/v1",
    "maxPayloadBytes": 64 * 1024 * 1024,
    "maxSharedHashes": 8_000_000,
    "maxSharedInputBytes": 64 * 1024 * 1024,
    "maxSharedJsonNodes": 1_000_000,
    "maxJsonDepth": 128,
    "maxIntegerBits": 16384,
    "includedPhases": (
        "raw-lexical-preflight", "ascii-decode", "strict-json-parse",
        "duplicate-and-integer-callback-reservation",
        "joint-envelope-and-independent-expectation-capture",
        "original-canonical-wire-comparison", "signature-callback-meter-stability",
        "genuine-signed-semantic-verification",
    ),
    "excludedWork": (
        "transport-buffer-acquisition", "indexed-projection-allocation",
        "fixed-metadata-scaffolding", "whole-process-memory", "whole-plan",
    ),
    "excludedAuthority": (
        "key-and-identity-enrollment", "before-root-and-cutoff-currentness",
        "capability-reservation", "one-use-persistence", "sql-commit",
        "registry-admission", "terminal-witness",
    ),
})
# Exact verifier evidence plus independent root-observation read surface.
# This is not planner/business row access or the pre-v9 outcome inventory.
VERIFIER_READ_CONTRACT = "serverware.policyAuthorityVerifierRead/v2"
VERIFIER_READ_TABLES = frozenset({
    "policy_authority_authenticated_table_roots",
    "policy_authority_counted_index_heads",
    "webauthn_challenges",
    "webauthn_credentials",
    "webauthn_trust_publication_high_water",
    "webauthn_trust_publications",
})
_AUDIT_COUNTER_REPLACEMENT_OPERATIONS = frozenset({
    "policy.activation.prepare", "policy.activation.abort", "policy.genesis.prepare",
    "rbac.binding.mutate", "control-approval.request", "control-approval.decide",
    "control-approval.consume", "control-approval.deny", "jit.request",
    "jit.review-receipt.issue", "jit.decide", "jit.deny",
})
_AUDIT_NEW_AGGREGATE_ROOT_OPERATIONS = frozenset({
    "webauthn.trust.stage", "webauthn.trust.complete", "webauthn.registration.create",
    "webauthn.registration.finalize", "webauthn.credential.revoke",
})
PROOF_PRIMITIVES = frozenset(
    {
        "primary-key-row",
        "bounded-limit-plus-one",
        "ordered-exact-page",
        "aggregate-high-water",
        "authenticated-secondary-index",
        authority_complete_query.PROOF_PRIMITIVE,
        "authenticated-root-delta",
        "capacity-reservation",
        "checked-arithmetic",
        "exact-derived-row-set",
        "logical-expiry-tombstone",
        "tombstone-row",
        "opaque-value-receipt",
        "sealed-value-receipt",
        "external-evidence-receipt",
    }
)
_TYPED_WEBAUTHN_CHALLENGE_OPERATIONS = frozenset(
    {
        "webauthn.challenge.create",
        "webauthn.challenge.claim",
        "webauthn.challenge.consume",
    }
)
_TYPED_SUCCESSOR_PLANNING_OPERATIONS = frozenset(
    {
        "webauthn.credential.revoke",
        "webauthn.registration.evidence.admit",
        "webauthn.registration.finalize",
        "webauthn.trust.complete",
        "webauthn.trust.installation.admit",
        "webauthn.trust.stage",
    }
)
_VERIFIED_ASSERTION_POLICIES = frozenset(
    {
        "bound-verified-assertion-receipt",
        "policy-bound-verified-assertion-receipt",
    }
)
REVOCATION_RETAINED_TABLE = "policy_authority_revocation_retained_plans"
REVOCATION_RETAINED_COLUMNS = (
    "planner_transaction_id", "plan_protocol", "exact_envelope_base64url",
    "exact_envelope_bytes_digest", "exact_envelope_byte_count",
    "evaluation_context_base64url", "evaluation_context_bytes_digest",
    "evaluation_context_byte_count", "planner_key_digest", "verifier_key_digest",
    "retained_record_digest", "source_revision",
)
REVOCATION_WRITER_REQUEST_TABLE = "policy_authority_revocation_writer_requests"
REVOCATION_WRITER_REQUEST_COLUMNS = (
    "intent_envelope_id", "relay_envelope_id", "execution_envelope_id",
    "planner_transaction_id", "plan_protocol", "retained_record_digest",
    "configuration_digest", "generation_sequence", "generation_digest",
    "exact_intent_base64url", "exact_intent_bytes_digest", "exact_intent_byte_count",
    "exact_relay_base64url", "exact_relay_bytes_digest", "exact_relay_byte_count",
    "historical_expectations_base64url", "historical_expectations_bytes_digest",
    "historical_expectations_byte_count", "planner_key_digest", "verifier_key_digest",
    "planned_at_epoch_ns", "source_revision",
)
REVOCATION_WRITER_REQUEST_CUSTODY_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthorityRevocationWriterRequestCustody/v1",
    "operation": "webauthn.credential.revoke", "planProtocol": "revocation-v4",
    "postgresOnly": True, "sqliteAdmission": False, "publicExecutionEnabled": False,
    "requestTable": REVOCATION_WRITER_REQUEST_TABLE,
    "requestColumns": REVOCATION_WRITER_REQUEST_COLUMNS,
    "primaryKey": ("intent_envelope_id",),
    "uniqueKeys": (("relay_envelope_id",), ("execution_envelope_id",),
                   ("intent_envelope_id", "configuration_digest", "generation_sequence",
                    "generation_digest", "source_revision")),
    "identityScope": "global-across-configuration-generation-and-key-rotations",
    "plannerBinding": "deferred-retained-plan-composite-foreign-key",
    "executionBinding": "deferred-execution-and-planner-composite-foreign-key",
    "maxControlBytes": 4 * 1024 * 1024, "maxHistoricalExpectationsBytes": 64 * 1024 * 1024,
    "planAndContextStorage": "existing-retained-plan-sidecar",
    "plannedAtBinding": "exact-original-stored-plan-time",
    "plannerPrivileges": ("SELECT", "INSERT"),
    "existingStoreMigration": "separately-reviewed-no-synthesis-or-cascade",
    "authorityExclusions": ("acknowledgement", "signature-verification", "key-enrollment",
                            "currentness", "semantic-replay", "execution", "witness"),
})
REVOCATION_WRITER_ACK_TABLE = "policy_authority_revocation_writer_acknowledgments"
REVOCATION_WRITER_ACK_COLUMNS = (
    "ack_envelope_id", "intent_envelope_id", "configuration_digest",
    "generation_sequence", "generation_digest", "writer_response_spki_digest",
    "exact_ack_base64url", "exact_ack_bytes_digest", "exact_ack_byte_count",
    "source_revision",
)
REVOCATION_WRITER_ACK_CUSTODY_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthorityRevocationWriterAckCustody/v1",
    "operation": "webauthn.credential.revoke", "planProtocol": "revocation-v4",
    "postgresOnly": True, "sqliteAdmission": False, "publicExecutionEnabled": False,
    "ackTable": REVOCATION_WRITER_ACK_TABLE, "ackColumns": REVOCATION_WRITER_ACK_COLUMNS,
    "primaryKey": ("ack_envelope_id",), "uniqueKeys": (("intent_envelope_id",),),
    "identityScope": "global-across-configuration-generation-and-key-rotations",
    "requestBinding": ("intent_envelope_id", "configuration_digest", "generation_sequence",
                       "generation_digest", "source_revision"),
    "requestForeignKey": "deferred-no-action-composite-foreign-key",
    "maxAckBytes": 16384, "plannerPrivileges": ("SELECT", "INSERT"),
    "existingStoreMigration": "separately-reviewed-no-synthesis-or-cascade",
    "authorityExclusions": ("signature-verification", "commit-completion", "key-enrollment",
                            "currentness", "semantic-replay", "execution", "witness",
                            "globally-exactly-once-signing"),
})
PLANNER_RESERVATION_IMMUTABLE_COLUMNS = (
    "planner_transaction_id", "plan_protocol", "operation", "operation_id", "request_digest",
    "capability_id", "operation_contract_digest", "query_manifest_digest",
    "selected_business_rows_json", "selected_business_rows_digest", "mutation_plan_json",
    "mutation_plan_digest", "work_units", "authority_root_set_before_digest",
    "planner_session_identity_digest", "planner_measurement_digest",
    "planner_attestation_receipt_digest", "deadline_monotonic_ns", "deadline_epoch_ns",
    "fence", "reserved_at_epoch_ns", "source_revision",
)
PLANNER_PAYLOAD_IMMUTABLE_COLUMNS = (
    "authorization_projection_digest", "authority_snapshot_digest", "exact_plan_base64url",
    "exact_plan_bytes_digest", "exact_plan_byte_count", "planned_at_epoch_ns", "retained_record_digest",
)
PLANNER_TERMINAL_IMMUTABLE_COLUMNS = (
    "status", "exact_response_base64url", "exact_response_bytes_digest", "exact_response_byte_count",
    "terminal_receipt_json", "terminal_receipt_digest", "terminal_at_epoch_ns",
)
REVOCATION_RETENTION_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthorityRevocationRetention/v1",
    "operation": "webauthn.credential.revoke",
    "planProtocol": "revocation-v4",
    "publicExecutionEnabled": False,
    "postgresOnly": True,
    "sqliteAdmission": False,
    "retainedTable": REVOCATION_RETAINED_TABLE,
    "retainedColumns": REVOCATION_RETAINED_COLUMNS,
    "reservationImmutableColumns": PLANNER_RESERVATION_IMMUTABLE_COLUMNS,
    "payloadImmutableColumns": PLANNER_PAYLOAD_IMMUTABLE_COLUMNS,
    "terminalImmutableColumns": PLANNER_TERMINAL_IMMUTABLE_COLUMNS,
    "recordSchema": "serverware.policyAuthorityRevocationRetainedPlan/v1",
    "contextSchema": "serverware.policyAuthorityRevocationEvaluationContext/v1",
    "contextFields": 18, "recordHeaderFields": 13,
    "maxEnvelopeBytes": 64 * 1024 * 1024,
    "maxContextBytes": 512 * 1024, "maxContextNodes": 4096, "maxContextDepth": 8,
    "parentBinding": "symmetric-deferred-composite-foreign-keys",
    "plannerPrivileges": ("SELECT", "INSERT"),
    "executorPrivileges": ("SELECT",),
    "legacyReplay": "explicit-v3-null-retained-digest-only",
    "existingStoreMigration": "separately-reviewed-no-synthesis-or-cascade",
    "authorityExclusions": ("stored-context", "key-enrollment", "currentness", "execution", "witness"),
})

# Separate content-addressed custody for three original evidence-plan bodies.
# This table is framework metadata, not a business mutation target, planner
# reservation, capability, or a new protocol value in the existing v3/v4 rows.
WEBAUTHN_EVIDENCE_RETAINED_TABLE = "policy_authority_webauthn_evidence_retained_plans"
WEBAUTHN_EVIDENCE_RETAINED_COLUMNS = (
    "retained_record_digest", "plan_protocol", "operation", "operation_id", "request_digest",
    "configuration_digest", "plan_digest", "exact_envelope_base64url",
    "exact_envelope_bytes_digest", "exact_envelope_byte_count", "original_inputs_base64url",
    "original_inputs_bytes_digest", "original_inputs_byte_count", "evaluation_context_base64url",
    "evaluation_context_bytes_digest", "evaluation_context_byte_count", "planner_key_digest",
    "evidence_key_digest", "source_revision", "retained_at_epoch_ns",
)
WEBAUTHN_EVIDENCE_RETENTION_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthorityWebAuthnEvidenceRetention/v1",
    "planProtocol": "webauthn-evidence-admission-v1",
    "operations": ("webauthn.registration.evidence.admit", "webauthn.trust.installation.admit"),
    "retainedTable": WEBAUTHN_EVIDENCE_RETAINED_TABLE,
    "retainedColumns": WEBAUTHN_EVIDENCE_RETAINED_COLUMNS,
    "primaryKey": ("retained_record_digest",),
    "identityScope": "content-addressed-original-plan-inputs-context-and-key-pins",
    "recordSchema": "serverware.policyAuthorityWebAuthnEvidenceAdmissionRetainedPlan/v1",
    "contextSchema": "serverware.policyAuthorityWebAuthnEvidencePlanEvaluationContext/v1",
    "contextFields": 20, "recordHeaderFields": 16,
    "maxEnvelopeBytes": 64 * 1024 * 1024,
    "maxOriginalInputsBytes": 64 * 1024 * 1024,
    "maxContextBytes": 64 * 1024 * 1024,
    "workOwnership": "existing-invocation-remaining-allowance/v1",
    "postgresOnly": True, "sqliteAdmission": False,
    "plannerPrivileges": ("SELECT", "INSERT"), "executorPrivileges": ("SELECT",),
    "immutability": "all-columns-update-delete-denied-truncate-privilege-denied",
    "retry": "full-original-byte-and-header-equality-preserve-first-timestamp",
    "transactionOwnership": "caller-owned-serializable-writer-with-nested-savepoint",
    "parentBinding": None, "publicExecutionEnabled": False,
    "existingStoreMigration": "separately-reviewed-no-synthesis-or-cascade",
    "authorityExclusions": ("stored-context", "key-enrollment", "historical-provenance", "currentness",
        "logical-attempt-reservation", "capability", "outer-commit", "execution", "witness"),
})

# Dedicated raw-four transition custody. Neither the content-addressed record
# nor its first retention time is a logical operation reservation or capability.
WEBAUTHN_TRANSITION_RETAINED_TABLE = "policy_authority_webauthn_transition_retained_plans"
WEBAUTHN_TRANSITION_RETAINED_COLUMNS = (
    "retained_record_digest", "plan_protocol", "operation", "operation_id", "request_digest",
    "configuration_digest", "plan_digest", "exact_envelope_base64url",
    "exact_envelope_bytes_digest", "exact_envelope_byte_count", "original_proof_base64url",
    "original_proof_bytes_digest", "original_proof_byte_count", "original_inputs_base64url",
    "original_inputs_bytes_digest", "original_inputs_byte_count", "evaluation_context_base64url",
    "evaluation_context_bytes_digest", "evaluation_context_byte_count", "planner_key_digest",
    "operation_key_digest", "source_revision", "retained_at_epoch_ns",
)
WEBAUTHN_TRANSITION_RETENTION_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthorityWebAuthnTransitionRetention/v1",
    "planProtocol": "webauthn-transition-v1",
    "operations": ("webauthn.registration.finalize", "webauthn.trust.stage", "webauthn.trust.complete"),
    "retainedTable": WEBAUTHN_TRANSITION_RETAINED_TABLE,
    "retainedColumns": WEBAUTHN_TRANSITION_RETAINED_COLUMNS,
    "primaryKey": ("retained_record_digest",),
    "identityScope": "content-addressed-original-plan-proof-inputs-context-and-key-pins",
    "recordSchema": "serverware.policyAuthorityWebAuthnTransitionRetainedPlan/v1",
    "contextSchema": "serverware.policyAuthorityWebAuthnTransitionPlanEvaluationContext/v1",
    "contextFields": 7, "recordHeaderFields": 18,
    "maxEnvelopeBytes": 64 * 1024 * 1024,
    "maxOriginalProofBytes": 64 * 1024 * 1024,
    "maxOriginalInputsBytes": 64 * 1024 * 1024,
    "maxContextBytes": 64 * 1024 * 1024,
    "maxAggregateOriginalBytes": 64 * 1024 * 1024,
    "workOwnership": "existing-invocation-remaining-allowance/v1",
    "postgresOnly": True, "sqliteAdmission": False,
    "plannerPrivileges": ("SELECT", "INSERT"), "executorPrivileges": ("SELECT",),
    "immutability": "all-columns-update-delete-denied-truncate-privilege-denied",
    "retry": "full-original-byte-and-header-equality-preserve-first-timestamp",
    "transactionOwnership": "caller-owned-serializable-writer-with-nested-savepoint",
    "parentBinding": None, "publicExecutionEnabled": False,
    "existingStoreMigration": "separately-reviewed-no-synthesis-or-cascade",
    "authorityExclusions": ("stored-context", "key-enrollment", "historical-provenance", "currentness",
        "logical-attempt-reservation", "capability", "outer-commit", "execution", "witness"),
})

# Protected transaction evidence, deliberately not an authenticated business
# row. The postcommit receipt commits this marker; the marker must not depend
# on that later receipt or on the external current-root completion receipt.
CURRENT_ROOT_COMMIT_MARKER_TABLE = "policy_authority_current_root_commit_markers"
CURRENT_ROOT_COMMIT_MARKER_COLUMNS = (
    "pending_decision_digest", "source_revision", "database_id", "enrollment_digest",
    "generation_digest", "pending_request_digest", "pending_sequence",
    "predecessor_sequence", "predecessor_head_digest", "fence", "operation",
    "request_digest", "operation_id", "capability_digest", "snapshot_digest",
    "before_vector_digest", "after_vector_digest", "result_digest",
)
SUCCESSOR_ISSUER_ROLE = "serverware_policy_authority_successor_issuer"
SUCCESSOR_EXECUTOR_ROLE = "serverware_policy_authority_successor_executor"
SUCCESSOR_RECOVERY_ROLE = "serverware_policy_authority_successor_recovery"
SUCCESSOR_ISSUE_FUNCTION = "serverware_policy_authority_issue_successor_execution"
SUCCESSOR_EXECUTE_FUNCTION = "serverware_policy_authority_execute_successor"
SUCCESSOR_READ_FUNCTION = "serverware_policy_authority_read_successor_execution"
SUCCESSOR_EXECUTION_FUNCTION_SIGNATURES = MappingProxyType({
    SUCCESSOR_ISSUE_FUNCTION: ("text", "text"),
    SUCCESSOR_EXECUTE_FUNCTION: ("text", "text"),
    SUCCESSOR_READ_FUNCTION: ("text", "text"),
})
SUCCESSOR_EXECUTION_CUSTODY_TABLE = "policy_authority_successor_execution_custody"
SUCCESSOR_EXECUTION_CUSTODY_COLUMNS = (
    "pending_decision_digest", "packet_digest", "packet_json", "enrollment_digest",
    "generation_digest", "capability_digest", "operation_id", "fence",
    "issued_at_epoch_ns", "expires_at_epoch_ns", "issuer_identity_digest",
)
SUCCESSOR_EXECUTION_CUSTODY_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthoritySuccessorExecutionCustody/v1",
    "table": SUCCESSOR_EXECUTION_CUSTODY_TABLE,
    "columns": SUCCESSOR_EXECUTION_CUSTODY_COLUMNS,
    "primaryKey": ("pending_decision_digest",),
    "uniqueKeys": (("packet_digest",), ("enrollment_digest", "capability_digest"),
        ("enrollment_digest", "operation_id"), ("enrollment_digest", "fence")),
    "issuerRole": SUCCESSOR_ISSUER_ROLE, "executorRole": SUCCESSOR_EXECUTOR_ROLE,
    "recoveryRole": SUCCESSOR_RECOVERY_ROLE,
    "issuerFunction": SUCCESSOR_ISSUE_FUNCTION, "executorFunction": SUCCESSOR_EXECUTE_FUNCTION,
    "recoveryFunction": SUCCESSOR_READ_FUNCTION,
    "functionArgumentTypes": ("text", "text"),
    "packetSchema": "serverware.policyAuthoritySuccessorExecutionPacket/v1",
    "maximumPacketBytes": 64 * 1024 * 1024,
    "directRuntimePrivileges": (), "directIssuerPrivileges": (), "directExecutorPrivileges": (),
    "directRecoveryPrivileges": (),
    "recoveryTransaction": "serializable-read-only-deferrable",
    "recoveryOriginals": "bounded-canonical-packet-originals-not-fresh-execution-authority",
    "recoveryHistoricalExpiry": "permitted-without-renewal-under-independent-live-retrieval-window",
    "postgresOnly": True, "sqliteAdmission": False, "publicExecutionEnabled": False,
    "immutability": "all-columns-update-delete-denied-truncate-privilege-denied",
    "frameworkCustodyExcludedFromBusinessRoots": True,
    "primaryMaintenance": False, "countedMaintenance": False,
    "catalogAdmission": "same-transaction-actual-full-manifest-against-independent-source-generated-pin",
    "issuerIdentityDomain": "serverware.policyAuthoritySuccessorIssuerSession/v1",
    "executorIdentityDomain": "serverware.policyAuthoritySuccessorExecutorSession/v1",
    "recoveryIdentityDomain": "serverware.policyAuthoritySuccessorRecoverySession/v1",
    "existingStoreMigration": "separately-reviewed-no-adoption-synthesis-or-cascade",
    "legacyOperationGates": "unchanged",
})
COMPLETION_READER_ROLE = "serverware_policy_authority_completion_reader"
COMPLETION_READ_CONTRACT = "serverware.policyAuthorityCompletionRead/v1"
COMPLETION_READ_TABLES = frozenset({
    CURRENT_ROOT_COMMIT_MARKER_TABLE,
    "policy_authority_authenticated_table_roots",
    "policy_authority_counted_index_heads",
})
CURRENT_ROOT_COMMIT_MARKER_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthorityCurrentRootCommitMarkerStorage/v1",
    "table": CURRENT_ROOT_COMMIT_MARKER_TABLE,
    "columns": CURRENT_ROOT_COMMIT_MARKER_COLUMNS,
    "primaryKey": ("pending_decision_digest",),
    "uniqueKeys": (("pending_request_digest",), ("enrollment_digest", "fence"),
        ("enrollment_digest", "operation_id"), ("enrollment_digest", "capability_digest")),
    "operations": ("webauthn.credential.revoke", "webauthn.registration.evidence.admit",
        "webauthn.registration.finalize", "webauthn.trust.complete",
        "webauthn.trust.installation.admit", "webauthn.trust.stage"),
    "sequenceBinding": "pending=predecessor+1",
    "snapshotIdentity": "source-controlled-canonical-digest-not-snapshot-v4-coercion",
    "postgresOnly": True, "sqliteAdmission": False,
    "runtimePrivileges": (), "verifierPrivileges": (), "plannerPrivileges": (),
    "issuerPrivileges": (), "executorPrivileges": ("SELECT",),
    "completionReaderRole": COMPLETION_READER_ROLE,
    "completionReaderPrivileges": ("SELECT",),
    "insertAuthority": "dedicated-protected-successor-consume-after-original-admission-and-root-checks",
    "installedInsertFunction": SUCCESSOR_EXECUTE_FUNCTION, "publicExecutionEnabled": False,
    "transactionOwnership": "same-transaction-as-business-writes-and-actual-after-vector",
    "immutability": "all-columns-update-delete-denied-truncate-privilege-denied",
    "frameworkCustodyExcludedFromBusinessRoots": True,
    "primaryMaintenance": False, "countedMaintenance": False,
    "postcommitBinding": "postcommit-receipt-commits-marker-not-marker-commits-receipt",
    "existingStoreMigration": "separately-reviewed-no-adoption-synthesis-or-cascade",
    "authorityExclusions": ("capability-admission", "currentness", "rollback-resistance",
        "missing-row-proof", "execution", "external-completion", "retry"),
})

REVOCATION_RETAINED_CAPABILITY_TABLE = "policy_authority_revocation_retained_capabilities"
REVOCATION_RETAINED_CAPABILITY_COLUMNS = (
    "capability_id", "capability_protocol", "capability_record_digest", "planner_transaction_id",
    "plan_protocol", "retained_record_digest", "execution_envelope_id", "capability_digest",
    "root_transition_digest", "authority_snapshot_digest", "exact_request_bytes_digest",
    "exact_capability_base64url", "exact_capability_bytes_digest", "exact_capability_byte_count",
    "signer_key_digest", "witness_key_digest", "exact_witness_request_base64url",
    "exact_witness_request_bytes_digest", "exact_witness_request_byte_count", "source_revision",
)
WRITER_CAPABILITY_IMMUTABLE_COLUMNS = (
    "capability_id", "capability_protocol", "capability_record_digest", "capability_digest",
    "envelope_id", "operation", "operation_id", "handler_name", "request_digest",
    "operation_manifest_digest", "query_manifest_digest", "authority_root_set_digest",
    "authority_snapshot_digest", "approver_policy_digest", "webauthn_receipt_json",
    "webauthn_receipt_digest", "webauthn_trust_high_water_digest", "witness_reservation_digest",
    "witness_sequence", "witness_head_digest", "deadline_monotonic_ns", "fence",
    "issued_monotonic_ns", "issued_at_epoch_ns", "expires_at_epoch_ns",
    "issuer_session_identity_digest", "issuer_measurement_digest", "issuer_attestation_receipt_digest",
    "issuer_credential_issuance_digest", "expected_result_digest", "planner_transaction_id",
    "authorization_projection_digest", "selected_business_rows_digest", "mutation_plan_digest",
    "deadline_epoch_ns",
)
WRITER_CAPABILITY_RESERVATION_COLUMNS = (
    "writer_token_digest", "reserved_at_epoch_ns", "reserved_transaction_id",
)
WRITER_CAPABILITY_TERMINAL_COLUMNS = (
    "status", *WRITER_CAPABILITY_RESERVATION_COLUMNS, "result_digest", "commit_receipt_digest",
    "committed_at_epoch_ns", "failure_digest", "failed_at_epoch_ns",
)
REVOCATION_CAPABILITY_CUSTODY_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthorityRevocationCapabilityCustody/v1",
    "operation": "webauthn.credential.revoke", "capabilityProtocol": "revocation-v4",
    "planProtocol": "revocation-v4", "postgresOnly": True, "sqliteAdmission": False,
    "installedSuccessorIssuer": True, "publicExecutionEnabled": False,
    "configuredServiceRoute": False, "issuerInterface": "private-load6-store8",
    "retainedTable": REVOCATION_RETAINED_CAPABILITY_TABLE,
    "retainedColumns": REVOCATION_RETAINED_CAPABILITY_COLUMNS,
    "identityImmutableColumns": WRITER_CAPABILITY_IMMUTABLE_COLUMNS,
    "reservationImmutableOnceSet": WRITER_CAPABILITY_RESERVATION_COLUMNS,
    "terminalColumns": WRITER_CAPABILITY_TERMINAL_COLUMNS,
    "maxSignedCapabilityBytes": 4 * 1024 * 1024, "maxSignedWitnessRequestBytes": 64 * 1024,
    "parentBinding": "symmetric-deferred-five-column-foreign-keys",
    "plannerBinding": "retained-plan-composite-foreign-key",
    "plannerCapabilityBinding": "genuine-verifier-and-private-issuer-comparison",
    "executionBinding": "primary-key-only-mutable-envelope",
    "issuerTablePrivileges": (),
    "existingStoreMigration": "separately-reviewed-no-synthesis-or-cascade",
    "authorityExclusions": ("signature-verification", "key-enrollment", "currentness", "execution", "witness"),
})

# PostgreSQL-only derived custody. These are not operation business tables,
# primary-tracked tables, or additions to SQLite's shared metadata schema.
POSTGRES_COUNTED_STORE_COLUMNS = MappingProxyType({
    "policy_authority_counted_index_heads": (
        "index_id", "table_name", "counted_profile", "projection_digest",
        "projection_manifest_digest", "index_revision", "root_digest", "leaf_count",
    ),
    "policy_authority_counted_index_leaves": (
        "index_id", "projection_digest", "index_key", "primary_id",
        "primary_key_digest", "primary_row_digest", "index_revision",
    ),
    "policy_authority_counted_index_nodes": (
        "index_id", "projection_digest", "depth", "path_prefix", "node_digest",
        "subtree_count", "index_revision",
    ),
})
POSTGRES_COUNTED_STORE_TABLES = tuple(POSTGRES_COUNTED_STORE_COLUMNS)
POSTGRES_COUNTED_FUNCTION_SIGNATURES = MappingProxyType({
    "serverware_policy_authority_counted_profile": ("text",),
    "serverware_policy_authority_counted_frame_digest": ("text", "text[]"),
    "serverware_policy_authority_counted_empty": ("text", "text"),
    "serverware_policy_authority_counted_leaf": ("text", "text", "text", "text"),
    "serverware_policy_authority_counted_branch": ("text", "text", "text[]", "bigint[]"),
    "serverware_policy_authority_counted_expiry_micros": ("text",),
    "serverware_policy_authority_counted_signed_order": ("bigint",),
    "serverware_policy_authority_counted_field": ("jsonb", "text", "text"),
    "serverware_policy_authority_counted_project": ("text", "jsonb"),
    "serverware_policy_authority_counted_apply_index": ("text", "text", "jsonb", "jsonb"),
    "serverware_policy_authority_counted_apply_event": ("text", "text", "jsonb", "jsonb"),
})
POSTGRES_COUNTED_FUNCTION_CONTRACTS = MappingProxyType({
    name: MappingProxyType({
        "argumentTypes": arguments,
        "language": "plpgsql",
        "securityDefiner": False,
        "strict": False,
        "volatility": "v" if name in {
            "serverware_policy_authority_counted_apply_index",
            "serverware_policy_authority_counted_apply_event",
        } else "i",
        "searchPath": ("pg_catalog",) if name in {
            "serverware_policy_authority_counted_expiry_micros",
            "serverware_policy_authority_counted_signed_order",
            "serverware_policy_authority_counted_field",
            "serverware_policy_authority_counted_project",
        } else ("pg_catalog", "$metadata", "pg_temp"),
    })
    for name, arguments in POSTGRES_COUNTED_FUNCTION_SIGNATURES.items()
})
POSTGRES_COUNTED_MAINTENANCE_CONTRACT = MappingProxyType({
    "schema": "serverware.policyAuthorityCountedMaintenanceAdmission/v1",
    "maximumProfilesPerNormalizedEvent": 3,
    "workAccounting": "bounded-per-profile-not-whole-operation",
    "plannerCompleteQueryAdmission": False,
    "sqliteInstalled": False,
})
_FRAMEWORK_CUSTODY_TABLES = frozenset(
    {
        *POSTGRES_COUNTED_STORE_TABLES,
        "policy_authority_authenticated_leaves",
        "policy_authority_authenticated_root_revisions",
        "policy_authority_authenticated_table_roots",
        "policy_authority_authenticated_tree_nodes",
        "policy_authority_authorization_projections",
        "policy_authority_authorization_dependency_manifests",
        "policy_authority_consumed_envelopes",
        "policy_authority_execution_envelopes",
        "policy_authority_external_witness_receipts",
        "policy_authority_fence_heads",
        "policy_authority_owner_contracts",
        "policy_authority_owner_decisions",
        "policy_authority_owner_operations",
        "policy_authority_operation_mutation_templates",
        "policy_authority_planner_transactions",
        REVOCATION_RETAINED_TABLE,
        REVOCATION_WRITER_REQUEST_TABLE,
        REVOCATION_WRITER_ACK_TABLE,
        REVOCATION_RETAINED_CAPABILITY_TABLE,
        WEBAUTHN_EVIDENCE_RETAINED_TABLE,
        WEBAUTHN_TRANSITION_RETAINED_TABLE,
        CURRENT_ROOT_COMMIT_MARKER_TABLE,
        SUCCESSOR_EXECUTION_CUSTODY_TABLE,
        "policy_authority_query_dependency_manifests",
        "policy_authority_schema_contracts",
        "policy_authority_verifier_capabilities",
        "policy_authority_v8_legacy_archive",
        "policy_authority_v8_offline_migration_receipts",
        "policy_authority_v9_offline_migration_receipts",
        "policy_authority_webauthn_assertion_evidence",
        "policy_authority_webauthn_assertion_receipts",
        "policy_authority_writer_capabilities",
        "policy_authority_writer_receipts",
    }
)
_AUTHORIZATION_SOURCE_TABLES = frozenset(
    {
        "control_plane_approvals",
        "credentials",
        "policy_candidate_artifacts",
        "policy_high_water",
        "policy_publications",
        "policy_authority_trusted_keys",
        "rbac_authority_state",
        "rbac_role_bindings",
        "routes",
        "webauthn_challenges",
        "webauthn_credentials",
        "webauthn_trust_publication_high_water",
        "webauthn_trust_publications",
    }
)
_BASE_FRAMEWORK_PRECONDITIONS = (
    "policy_authority_fence_heads",
    "policy_authority_writer_capabilities",
    "policy_authority_query_dependency_manifests",
    "policy_authority_authorization_dependency_manifests",
    "policy_authority_authorization_projections",
    "policy_authority_execution_envelopes",
    "policy_authority_planner_transactions",
)
_BASE_FRAMEWORK_WRITES = (
    "policy_authority_authenticated_leaves",
    "policy_authority_authenticated_root_revisions",
    "policy_authority_authenticated_table_roots",
    "policy_authority_authenticated_tree_nodes",
    "policy_authority_authorization_projections",
    "policy_authority_consumed_envelopes",
    "policy_authority_execution_envelopes",
    "policy_authority_planner_transactions",
    "policy_authority_writer_capabilities",
    "policy_authority_writer_receipts",
)
EXECUTOR_ARGUMENT_TYPES = ("text", "text", "text", "text", "text")
CAPABILITY_ISSUER_FUNCTION_SIGNATURES = MappingProxyType(
    {
        "serverware_policy_authority_issue_capability": (
            "text",
            "text",
            "text",
            "text",
        ),
        "serverware_policy_authority_issue_writer_capability": (
            "text",
            "text",
            "text",
            "text",
            "text",
        ),
        "serverware_policy_authority_record_witness_receipt": (
            "text",
            "text",
            "text",
            "text",
        ),
    }
)
CAPABILITY_ISSUER_FUNCTION_ARGUMENTS = MappingProxyType(
    {
        "serverware_policy_authority_issue_capability": (
            "capability_json",
            "supplied_capability_digest",
            "supplied_issuer_measurement_digest",
            "supplied_issuer_attestation_receipt_digest",
        ),
        "serverware_policy_authority_issue_writer_capability": (
            "capability_json",
            "supplied_capability_digest",
            "supplied_issuer_measurement_digest",
            "supplied_issuer_attestation_receipt_digest",
            "supplied_issuer_credential_issuance_digest",
        ),
        "serverware_policy_authority_record_witness_receipt": (
            "witness_receipt_json",
            "supplied_witness_receipt_digest",
            "supplied_issuer_measurement_digest",
            "supplied_issuer_attestation_receipt_digest",
        ),
    }
)
REVOCATION_CAPABILITY_ISSUER_FUNCTION_SIGNATURES = MappingProxyType(
    {
        "serverware_policy_authority_load_revocation_issuance": ("text",) * 6,
        "serverware_policy_authority_issue_revocation_capability": ("text",) * 8,
    }
)
REVOCATION_CAPABILITY_ISSUER_FUNCTION_ARGUMENTS = MappingProxyType(
    {
        "serverware_policy_authority_load_revocation_issuance": (
            "supplied_planner_transaction_id", "supplied_execution_envelope_id",
            "supplied_capability_id", "supplied_issuer_measurement_digest",
            "supplied_issuer_attestation_receipt_digest",
            "supplied_issuer_credential_issuance_digest",
        ),
        "serverware_policy_authority_issue_revocation_capability": (
            "supplied_original_capability_base64url",
            "supplied_original_witness_request_base64url",
            "supplied_capability_record_digest", "supplied_signer_key_digest",
            "supplied_witness_key_digest", "supplied_issuer_measurement_digest",
            "supplied_issuer_attestation_receipt_digest",
            "supplied_issuer_credential_issuance_digest",
        ),
    }
)
OFFLINE_MIGRATION_RECEIPT_PRODUCERS = MappingProxyType(
    {
        V8_TO_V9_MIGRATION_CONTRACT_ID: MappingProxyType(
            {
                "handler": V8_TO_V9_MIGRATION_RECEIPT_HANDLER,
                "arguments": (
                    "migration_sha256",
                    "before_manifest_json",
                    "before_row_counts_json",
                    "after_manifest_json",
                    "after_row_counts_json",
                    "signer_public_key_base64url",
                    "detached_signature",
                    "completed_at",
                    "connection",
                ),
            }
        )
    }
)
OFFLINE_MIGRATION_RECEIPT_HANDLER_TO_CONTRACT = MappingProxyType(
    {
        str(spec["handler"]): contract_id
        for contract_id, spec in OFFLINE_MIGRATION_RECEIPT_PRODUCERS.items()
    }
)


@dataclass(frozen=True, slots=True)
class AuthorityOperation:
    handler: str
    planning_adapter_id: str
    business_reads: tuple[str, ...]
    business_writes: tuple[str, ...]
    business_read_before_write: tuple[str, ...]
    authorization_reads: tuple[str, ...]
    framework_preconditions: tuple[str, ...]
    framework_writes: tuple[str, ...]
    framework_read_before_write: tuple[str, ...]
    selectors: Mapping[str, tuple[tuple[str, ...], ...]]
    webauthn: str
    assertion_required: bool
    approver_policy_required: bool
    predicate_closure: str
    selector_closure: str
    proof_kind: str
    mutation_kinds: Mapping[str, tuple[str, ...]]
    proof_primitives: tuple[str, ...]
    maximum_query_rows: int
    maximum_mutations: int
    maximum_work_units: int
    external_evidence_types: tuple[str, ...]
    opaque_value_kinds: tuple[str, ...]

    def compatibility_mapping(self, operation: str) -> Mapping[str, Any]:
        audit_capacity = "metadata_audit_outbox" in self.business_writes
        replaced_slots = int(operation in _AUDIT_COUNTER_REPLACEMENT_OPERATIONS)
        adds_aggregate_root = operation in _AUDIT_NEW_AGGREGATE_ROOT_OPERATIONS
        if (replaced_slots or adds_aggregate_root) and not audit_capacity:
            raise ValueError("audit framework allowance is outside its source operation")
        business_query_rows = self.maximum_query_rows - replaced_slots
        business_mutations = self.maximum_mutations - replaced_slots
        reads = tuple(
            sorted(
                set(self.business_reads)
                | set(self.business_writes)
                | set(self.business_read_before_write)
                | set(self.authorization_reads)
                | set(self.framework_preconditions)
                | set(self.framework_writes)
                | set(self.framework_read_before_write)
            )
        )
        writes = tuple(
            sorted(
                set(self.business_writes) | set(self.framework_writes)
            )
        )
        return MappingProxyType(
            {
                "handler": self.handler,
                "planningAdapterId": self.planning_adapter_id,
                "transitionProgramId":
                    _transition_program_id(operation, self.handler),
                "planningMode": (
                    "intentionally-disabled"
                    if operation == "jit.consume"
                    else "typed-webauthn-challenge"
                    if operation
                        in _TYPED_WEBAUTHN_CHALLENGE_OPERATIONS
                    else "typed-successor-planning"
                    if operation in _TYPED_SUCCESSOR_PLANNING_OPERATIONS
                    else "typed-pure-transition"
                ),
                "businessReads": self.business_reads,
                "businessWrites": self.business_writes,
                "businessReadBeforeWrite":
                    self.business_read_before_write,
                "authorizationReads": self.authorization_reads,
                "frameworkPreconditions": self.framework_preconditions,
                "frameworkWrites": self.framework_writes,
                "frameworkReadBeforeWrite":
                    self.framework_read_before_write,
                "mutationTemplates":
                    _mutation_templates(
                        operation,
                        self.business_writes,
                        self.mutation_kinds,
                    ),
                "proofPrimitives": self.proof_primitives,
                "globalAuditCapacity": audit_capacity,
                "auditCapacityCounterSlotsReplaced": replaced_slots,
                "auditCapacityAddsAggregateRoot": adds_aggregate_root,
                "maximumBusinessQueryRows": business_query_rows,
                "maximumBusinessMutations": business_mutations,
                "maximumBusinessWorkUnits": self.maximum_work_units,
                "maximumQueryRows": business_query_rows + int(audit_capacity),
                "maximumMutations": business_mutations + int(audit_capacity),
                "maximumWorkUnits": self.maximum_work_units + 2 * int(audit_capacity),
                "externalEvidenceTypes": self.external_evidence_types,
                "opaqueValueKinds": self.opaque_value_kinds,
                "reads": reads,
                "writes": writes,
                "selectors": self.selectors,
                "webauthn": self.webauthn,
                "assertionRequired": self.assertion_required,
                "approverPolicyRequired":
                    self.approver_policy_required,
                "predicateClosure": self.predicate_closure,
                "selectorClosure": self.selector_closure,
                "proofKind": self.proof_kind,
            }
        )


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _digest(domain: str, value: Any) -> str:
    framed = _canonical(value)
    hasher = hashlib.sha256()
    encoded_domain = domain.encode("ascii")
    hasher.update(len(encoded_domain).to_bytes(8, "big"))
    hasher.update(encoded_domain)
    hasher.update(len(framed).to_bytes(8, "big"))
    hasher.update(framed)
    return "sha256:" + hasher.hexdigest()


def _executor_function_name(operation: str) -> str:
    operation_stem = "".join(
        character if character.isalnum() else "_"
        for character in operation.lower()
    ).strip("_")
    suffix = hashlib.sha256(operation.encode("ascii")).hexdigest()[:12]
    prefix = "serverware_policy_authority_execute_"
    tail = f"_{suffix}_v9"
    return prefix + operation_stem[:63 - len(prefix) - len(tail)] + tail


_MUTATION_KIND_OVERRIDES = MappingProxyType(
    {
        (
            "webauthn.trust.error",
            "webauthn_trust_publications",
        ): ("UPDATE",),
        (
            "webauthn.counter.cas",
            "webauthn_credentials",
        ): ("UPDATE",),
        (
            "webauthn.challenge.claim",
            "webauthn_challenges",
        ): ("UPDATE",),
        (
            "webauthn.challenge.consume",
            "webauthn_challenges",
        ): ("UPDATE",),
    }
)
_TABLE_MUTATION_KIND_DEFAULTS = MappingProxyType(
    {
        "policy_authority_bounded_aggregate_states": ("UPDATE",),
        "policy_authority_external_evidence_receipts": ("UPDATE",),
        "policy_authority_opaque_values": ("UPDATE",),
        "policy_authority_sealed_values": ("UPDATE",),
        "policy_authority_continuations": ("INSERT", "UPDATE"),
        "policy_authority_secondary_index_heads": ("UPDATE",),
        "policy_authority_tombstones": ("INSERT",),
        "policy_authority_work_pages": ("INSERT", "UPDATE"),
    }
)


def _transition_program_id(operation: str, handler: str) -> str:
    return (
        "serverware.policyAuthorityTransition/"
        + operation
        + "/"
        + _digest(
            "serverware.policyAuthorityTransitionProgram/v1",
            {"operation": operation, "handler": handler},
        )[7:23]
        + "/v1"
    )


def _mutation_templates(
    operation: str,
    business_writes: tuple[str, ...],
    mutation_kinds: Mapping[str, tuple[str, ...]] | None = None,
) -> tuple[Mapping[str, Any], ...]:
    templates: list[Mapping[str, Any]] = []
    for table in business_writes:
        table_mutation_kinds = (
            tuple(mutation_kinds[table])
            if mutation_kinds is not None and table in mutation_kinds
            else _MUTATION_KIND_OVERRIDES.get(
                (operation, table),
                _TABLE_MUTATION_KIND_DEFAULTS.get(
                    table,
                    ("INSERT", "UPDATE"),
                ),
            )
        )
        for mutation in table_mutation_kinds:
            before = "absent" if mutation == "INSERT" else "present"
            template = {
                "schema":
                    "serverware.policyAuthorityMutationTemplate/v1",
                "operation": operation,
                "table": table,
                "mutation": mutation,
                "before": before,
                "after": (
                    "absent" if mutation == "DELETE" else "present"
                ),
                "predicate":
                    "exact-primary-key-and-full-row-cas-v1",
                "cardinality": 1,
            }
            template["templateId"] = _digest(
                "serverware.policyAuthorityMutationTemplate/v1",
                template,
            )
            templates.append(MappingProxyType(template))
    return tuple(templates)


def _spec(
    handler: str,
    *,
    reads: tuple[str, ...],
    writes: tuple[str, ...],
    selectors: Mapping[str, tuple[tuple[str, ...], ...]] | None = None,
    webauthn: str = "not-required",
    approver_policy: bool = False,
    mutation_kinds: (
        Mapping[str, tuple[str, ...]] | None
    ) = None,
    proof_primitives: tuple[str, ...] = ("primary-key-row",),
    maximum_query_rows: int = MAX_QUERY_PROOFS,
    maximum_mutations: int = MAX_MUTATIONS,
    maximum_work_units: int = MAX_WORK_UNITS,
    external_evidence_types: tuple[str, ...] = (),
    opaque_value_kinds: tuple[str, ...] = (),
) -> AuthorityOperation:
    planning_adapter_id = (
        "serverware.policyAuthorityPlanningAdapter/"
        f"{handler}/v1"
    )
    assertion_required = webauthn in _VERIFIED_ASSERTION_POLICIES
    assertion_business_writes = (
        {
            "webauthn_challenges",
            "webauthn_credentials",
        }
        if assertion_required
        else set()
    )
    assertion_authorization_reads = (
        assertion_business_writes
        | {
            "webauthn_trust_publications",
            "webauthn_trust_publication_high_water",
        }
        if assertion_required
        else set()
    )
    declared_writes = (
        set(writes) | assertion_business_writes
    )
    if declared_writes & _FRAMEWORK_CUSTODY_TABLES:
        raise ValueError(
            "framework custody table was declared as a business write"
        )
    declared_reads = (
        set(reads)
        | declared_writes
        | assertion_authorization_reads
    )
    if declared_reads & _FRAMEWORK_CUSTODY_TABLES:
        raise ValueError(
            "framework custody table was declared as a business read"
        )
    authorization_reads = tuple(
        sorted(
            (
                declared_reads & _AUTHORIZATION_SOURCE_TABLES
            )
            - declared_writes
        )
    )
    business_writes = tuple(sorted(declared_writes))
    business_read_before_write = business_writes
    business_reads = tuple(
        sorted(
            declared_reads
            - set(business_writes)
            - set(authorization_reads)
            - _FRAMEWORK_CUSTODY_TABLES
        )
    )
    declared_framework_preconditions = (
        set(_BASE_FRAMEWORK_PRECONDITIONS)
        | ({REVOCATION_RETAINED_TABLE} if handler == "revoke_webauthn_credential" else set())
        | (
            {"policy_authority_webauthn_assertion_evidence"}
            if assertion_required
            else set()
        )
    )
    declared_framework_writes = (
        set(_BASE_FRAMEWORK_WRITES)
        | (
            {"policy_authority_webauthn_assertion_evidence"}
            if assertion_required
            else set()
        )
    )
    framework_read_before_write = tuple(
        sorted(
            declared_framework_preconditions
            & declared_framework_writes
        )
    )
    framework_preconditions = tuple(
        sorted(
            declared_framework_preconditions
            - declared_framework_writes
        )
    )
    framework_writes = tuple(sorted(declared_framework_writes))
    categories = (
        set(business_reads),
        set(business_writes),
        set(authorization_reads),
        set(framework_preconditions),
        set(framework_writes),
    )
    if any(
        left & right
        for ordinal, left in enumerate(categories)
        for right in categories[ordinal + 1:]
    ):
        raise ValueError("authority dependency categories overlap")
    selector_program = {
        table: tuple(tuple(path) for path in paths)
        for table, paths in sorted((selectors or {}).items())
    }
    business_relations = set(business_reads) | set(business_writes)
    if set(selector_program) - business_relations:
        raise ValueError("selector table is outside the closed relation set")
    selector_count = sum(len(paths) for paths in selector_program.values())
    if selector_count > MAX_SELECTORS_PER_OPERATION:
        raise ValueError("operation exceeds its selector proof bound")
    mutation_program = {
        table: tuple(kinds)
        for table, kinds in (mutation_kinds or {}).items()
    }
    if (
        set(mutation_program) - set(business_writes)
        or any(
            not kinds
            or len(set(kinds)) != len(kinds)
            or any(
                kind not in {"INSERT", "UPDATE", "DELETE"}
                for kind in kinds
            )
            for kinds in mutation_program.values()
        )
        or not proof_primitives
        or len(set(proof_primitives)) != len(proof_primitives)
        or set(proof_primitives) - PROOF_PRIMITIVES
        or not 1 <= maximum_query_rows <= MAX_QUERY_PROOFS
        or not 1 <= maximum_mutations <= MAX_MUTATIONS
        or not 1 <= maximum_work_units <= MAX_WORK_UNITS
        or tuple(sorted(set(external_evidence_types)))
            != external_evidence_types
        or tuple(sorted(set(opaque_value_kinds)))
            != opaque_value_kinds
    ):
        raise ValueError("authority bounded transition program is invalid")
    return AuthorityOperation(
        handler=handler,
        planning_adapter_id=planning_adapter_id,
        business_reads=business_reads,
        business_writes=business_writes,
        business_read_before_write=business_read_before_write,
        authorization_reads=authorization_reads,
        framework_preconditions=framework_preconditions,
        framework_writes=framework_writes,
        framework_read_before_write=framework_read_before_write,
        selectors=MappingProxyType(selector_program),
        webauthn=webauthn,
        assertion_required=assertion_required,
        approver_policy_required=approver_policy,
        predicate_closure="incremental-authenticated-relation-root-v3",
        selector_closure="explicit-argument-path-v1",
        proof_kind="radix16-canonical-multiproof-v2",
        mutation_kinds=MappingProxyType(mutation_program),
        proof_primitives=proof_primitives,
        maximum_query_rows=maximum_query_rows,
        maximum_mutations=maximum_mutations,
        maximum_work_units=maximum_work_units,
        external_evidence_types=external_evidence_types,
        opaque_value_kinds=opaque_value_kinds,
    )


_AUDIT = ("metadata_audit_outbox", "policy_authority_transition_audits")
_APPROVAL = (
    "approval_requests",
    "approval_review_receipts",
    "approval_grants",
    "approval_grant_consumptions",
    "approval_request_decisions",
)
_CONTROL_APPROVAL = (
    "control_plane_approvals",
    "webauthn_challenges",
    "webauthn_credentials",
    "webauthn_trust_publications",
)
_QUOTA = (
    "rate_limit_counters",
    "durable_budget_definitions",
    "durable_budget_events",
    "traversal_budget_chains",
    "traversal_budget_cursors",
    "traversal_budget_page_reservations",
    "policy_state_bundles",
)
_POLICY_STATE_WRITES = tuple(
    table for table in _QUOTA if table != "rate_limit_counters"
)
_POLICY_STATE_DISPATCH_WRITES = tuple(
    table
    for table in _POLICY_STATE_WRITES
    if table != "traversal_budget_cursors"
)
_RELEASE = (
    "release_authorization_attempts",
    "release_authorization_credential_issuances",
    "release_authorization_quota_reservations",
    "release_authorization_events",
    "credential_lease_nonces",
    "credential_lease_replay_state",
)
_RELEASE_RESERVE_WRITES = (
    "approval_grants",
    "approval_requests",
    "durable_budget_definitions",
    "durable_budget_events",
    "metadata_audit_outbox",
    "policy_state_bundles",
    "rate_limit_counters",
    "release_authorization_attempts",
    "release_authorization_events",
    "release_authorization_quota_reservations",
    "routes",
    "traversal_budget_chains",
    "traversal_budget_cursors",
    "traversal_budget_page_reservations",
)
_RELEASE_V1_TRANSITION_WRITES = (
    "approval_grants",
    "approval_grant_consumptions",
    "rate_limit_counters",
    "release_authorization_attempts",
    "release_authorization_events",
    "release_authorization_quota_reservations",
)
_RELEASE_POLICY_TRANSITION_WRITES = (
    _RELEASE_V1_TRANSITION_WRITES
    + (
        "durable_budget_definitions",
        "durable_budget_events",
        "policy_state_bundles",
        "traversal_budget_chains",
        "traversal_budget_cursors",
        "traversal_budget_page_reservations",
    )
)
_RELEASE_CANCEL_WRITES = (
    "approval_grants",
    "rate_limit_counters",
    "release_authorization_attempts",
    "release_authorization_events",
    "release_authorization_quota_reservations",
)
_RELEASE_CREDENTIAL_CLAIM_WRITES = (
    _RELEASE_CANCEL_WRITES
    + ("release_authorization_credential_issuances",)
)
_WEBAUTHN = (
    "webauthn_challenges",
    "webauthn_credentials",
    "webauthn_trust_publications",
)
_VERIFIED_APPROVAL_AUTHORITY = (
    "policy_high_water",
    "policy_publications",
    "rbac_authority_state",
    "rbac_role_bindings",
    "webauthn_trust_publication_high_water",
)
_RELEASE_AUTHORITY = _VERIFIED_APPROVAL_AUTHORITY + ("credentials",)
_POLICY_COMMON = (
    "policy_activation_attempts",
    "policy_activation_heads",
    "policy_activation_preparations",
    "policy_activation_prepared_transitions",
    "policy_high_water",
    "policy_publications",
    "policy_candidate_artifacts",
    "control_plane_approvals",
    "webauthn_trust_publications",
    "rbac_authority_state",
    "rbac_role_bindings",
)
_EXPORT = (
    "policy_activation_finalized_exports",
    "policy_activation_export_issuances",
    "policy_activation_export_pages",
    "policy_activation_export_attestations",
    "policy_activation_export_page_attestations",
    "policy_activation_export_authorizations",
    "policy_activation_export_authorization_receipts",
    "policy_activation_export_authorization_heads",
)
_PHASE2_AGGREGATE = ("policy_authority_bounded_aggregate_states",)
_PHASE2_EXACT_PAGE = ("policy_authority_exact_pages",)
_PHASE2_WORK_PAGE = ("policy_authority_work_pages",)
_PHASE2_TOMBSTONE = ("policy_authority_tombstones",)
_PHASE2_OPAQUE = ("policy_authority_opaque_values",)
_PHASE2_EVIDENCE = ("policy_authority_external_evidence_receipts",)
_PHASE3_CONTINUATION = (
    "policy_authority_continuations",
    "policy_authority_secondary_index_heads",
)
_PHASE3_SEALED = ("policy_authority_sealed_values",)
_PHASE3_ACTIVATION_EVIDENCE = (
    "policy_authority_activation_evidence_bindings",
)
# Source-owned storage/ACL inventory, not a generic immutability policy.
# Some primitives require measured UPDATE/INSERT operations; none may inherit
# the ordinary metadata runtime's broad table DML grant. Keep this independent
# of current kernel registration, since missing kernels must not grant access.
PHASE2_STORE_TABLES = tuple(sorted({
    *_PHASE2_AGGREGATE,
    *_PHASE2_EXACT_PAGE,
    *_PHASE2_WORK_PAGE,
    *_PHASE2_TOMBSTONE,
    *_PHASE2_OPAQUE,
    *_PHASE2_EVIDENCE,
    *_PHASE3_CONTINUATION,
    *_PHASE3_SEALED,
    *_PHASE3_ACTIVATION_EVIDENCE,
}))
V9_ADDITIONAL_PROTECTED_TABLES = tuple(sorted({
    *PHASE2_STORE_TABLES,
    SUCCESSOR_EXECUTION_CUSTODY_TABLE,
    "policy_authority_authorization_dependency_manifests",
    "policy_authority_operation_mutation_templates",
}))
_PHASE2_MAINTENANCE = (
    _PHASE2_AGGREGATE
    + _PHASE2_WORK_PAGE
    + _PHASE2_TOMBSTONE
    + _PHASE3_CONTINUATION
)
_PHASE2_RELEASE_STATE = (
    _PHASE2_AGGREGATE
    + _PHASE2_EXACT_PAGE
    + _PHASE2_OPAQUE
    + _PHASE3_SEALED
    + _PHASE2_EVIDENCE
)
_PHASE2_EXACT_AGGREGATE_PROOF_SET = (
    "primary-key-row",
    "ordered-exact-page",
    "aggregate-high-water",
    "capacity-reservation",
    "checked-arithmetic",
    "exact-derived-row-set",
)
_PHASE2_MAINTENANCE_PROOF_SET = (
    _PHASE2_EXACT_AGGREGATE_PROOF_SET
    + (
        "logical-expiry-tombstone",
        "tombstone-row",
        "bounded-limit-plus-one",
        "authenticated-secondary-index",
    )
)
_PHASE2_OPAQUE_PROOF_SET = _PHASE2_EXACT_AGGREGATE_PROOF_SET + (
    "opaque-value-receipt",
    "external-evidence-receipt",
)
_PHASE2_MAINTENANCE_OPAQUE_PROOF_SET = (
    _PHASE2_MAINTENANCE_PROOF_SET
    + (
        "opaque-value-receipt",
        "sealed-value-receipt",
        "external-evidence-receipt",
    )
)


_OPERATIONS = {
    "policy.activation.prepare": _spec(
        "serverware_policy_authority_prepare",
        reads=_POLICY_COMMON
        + (
            "policy_activation_approvals",
            "policy_activation_approval_members",
            "policy_activation_webauthn_assertions",
            "policy_activation_finalizations",
            "policy_activation_aborts",
            "policy_canaries",
            "policy_shadow_generation_publications",
        )
        + _PHASE2_EXACT_PAGE
        + _PHASE2_EVIDENCE
        + _PHASE3_ACTIVATION_EVIDENCE,
        writes=(
            "policy_activation_approvals",
            "policy_activation_approval_members",
            "policy_activation_webauthn_assertions",
            "policy_activation_attempts",
            "policy_activation_preparations",
            "policy_activation_prepared_transitions",
        )
        + _AUDIT
        + _PHASE2_AGGREGATE
        + _PHASE2_EVIDENCE
        + _PHASE3_ACTIVATION_EVIDENCE,
        mutation_kinds={
            "policy_authority_activation_evidence_bindings": ("INSERT",),
        },
        webauthn="bound-verified-assertion-receipt",
        proof_primitives=_PHASE2_EXACT_AGGREGATE_PROOF_SET
            + ("external-evidence-receipt",),
        external_evidence_types=(
            "decision-gate-publication-chain/v1",
            "policy-signature-verification/v1",
        ),
    ),
    "policy.activation.record-inclusion": _spec(
        "serverware_policy_authority_record_inclusion",
        reads=(
            "policy_activation_preparations",
            "policy_activation_prepared_transitions",
            "policy_authority_audit_inclusion_heads",
            "policy_authority_audit_inclusion_receipts",
            "policy_authority_evidence_verifications",
            "policy_authority_genesis_preparations",
            "policy_shadow_generation_publications",
        )
        + _PHASE2_EXACT_PAGE
        + _PHASE2_EVIDENCE
        + _PHASE3_ACTIVATION_EVIDENCE,
        writes=(
            "policy_authority_evidence_verifications",
            "policy_shadow_generation_publications",
            "policy_authority_audit_inclusion_receipts",
            "policy_authority_audit_inclusion_heads",
        )
        + _PHASE2_AGGREGATE
        + _PHASE2_EVIDENCE,
        webauthn="bound-verified-assertion-receipt",
        proof_primitives=_PHASE2_EXACT_AGGREGATE_PROOF_SET
            + ("external-evidence-receipt",),
        external_evidence_types=(
            "audit-inclusion/v1",
            "decision-gate-publication-chain/v1",
        ),
    ),
    "policy.activation.finalize": _spec(
        "serverware_policy_authority_finalize",
        reads=_POLICY_COMMON
        + (
            "policy_activation_approvals",
            "policy_activation_approval_members",
            "policy_activation_webauthn_assertions",
            "policy_activation_approval_consumptions",
            "policy_activation_finalizations",
            "policy_activation_aborts",
            "policy_shadow_generation_publications",
            "policy_authority_audit_inclusion_receipts",
            "policy_authority_evidence_verifications",
        )
        + _PHASE2_EXACT_PAGE
        + _PHASE2_EVIDENCE
        + _PHASE3_ACTIVATION_EVIDENCE,
        writes=(
            "control_plane_approvals",
            "policy_activation_aborts",
            "policy_activation_approvals",
            "policy_activation_approval_members",
            "policy_activation_webauthn_assertions",
            "policy_activation_approval_consumptions",
            "policy_activation_rollback_consumptions",
            "policy_activation_revisions",
            "policy_canary_revisions",
            "policy_activation_heads",
            "policy_canary_heads",
            "policy_publications",
            "policy_high_water",
            "policy_activation_publication_receipts",
            "policy_activation_finalizations",
            "policy_activation_finalized_exports",
            "policy_authority_evidence_verifications",
        )
        + _AUDIT
        + _PHASE2_AGGREGATE
        + _PHASE2_EVIDENCE
        + _PHASE3_ACTIVATION_EVIDENCE,
        mutation_kinds={
            "policy_authority_activation_evidence_bindings": ("UPDATE",),
        },
        webauthn="bound-verified-assertion-receipt",
        proof_primitives=_PHASE2_EXACT_AGGREGATE_PROOF_SET
            + ("external-evidence-receipt",),
        external_evidence_types=(
            "audit-inclusion/v1",
            "decision-gate-publication-chain/v1",
        ),
    ),
    "policy.activation.abort": _spec(
        "serverware_policy_authority_abort",
        reads=(
            "policy_activation_preparations",
            "policy_activation_finalizations",
            "policy_activation_aborts",
            "policy_shadow_generation_publications",
        )
        + _PHASE2_AGGREGATE
        + _PHASE2_EVIDENCE
        + _PHASE3_ACTIVATION_EVIDENCE,
        writes=(
            ("policy_activation_aborts",)
            + _AUDIT
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
            + _PHASE3_ACTIVATION_EVIDENCE
        ),
        mutation_kinds={
            "policy_authority_activation_evidence_bindings": ("UPDATE",),
        },
        webauthn="bound-verified-assertion-receipt",
        proof_primitives=(
            "primary-key-row",
            "aggregate-high-water",
            "capacity-reservation",
            "external-evidence-receipt",
        ),
        external_evidence_types=(
            "decision-gate-publication-chain/v1",
        ),
        maximum_query_rows=8,
        maximum_mutations=8,
        maximum_work_units=96,
    ),
    "policy.genesis.prepare": _spec(
        "serverware_policy_authority_genesis_prepare",
        reads=(
            "policy_authority_genesis_preparations",
            "policy_authority_genesis_finalizations",
            "policy_authority_trusted_keys",
            "policy_high_water",
            "policy_publications",
        )
        + _PHASE2_AGGREGATE
        + _PHASE2_EVIDENCE,
        writes=(
            "policy_authority_evidence_verifications",
            "policy_authority_genesis_preparations",
        )
        + _AUDIT
        + _PHASE2_AGGREGATE
        + _PHASE2_EVIDENCE,
        webauthn="bound-verified-assertion-receipt",
        proof_primitives=_PHASE2_EXACT_AGGREGATE_PROOF_SET
            + ("external-evidence-receipt",),
        external_evidence_types=(
            "policy-signature-verification/v1",
        ),
    ),
    "policy.genesis.finalize": _spec(
        "serverware_policy_authority_genesis_finalize",
        reads=(
            "policy_authority_genesis_preparations",
            "policy_authority_genesis_finalizations",
            "policy_authority_audit_inclusion_receipts",
            "policy_high_water",
            "policy_publications",
        )
        + _PHASE2_AGGREGATE
        + _PHASE2_EVIDENCE,
        writes=(
            "policy_authority_evidence_verifications",
            "policy_authority_audit_inclusion_receipts",
            "policy_authority_audit_inclusion_heads",
            "policy_authority_genesis_finalizations",
            "policy_publications",
            "policy_high_water",
        )
        + _PHASE2_AGGREGATE
        + _PHASE2_EVIDENCE,
        webauthn="bound-verified-assertion-receipt",
        proof_primitives=_PHASE2_EXACT_AGGREGATE_PROOF_SET
            + ("external-evidence-receipt",),
        external_evidence_types=("audit-inclusion/v1",),
    ),
    "policy.export.freeze": _spec(
        "prepare_policy_activation_chain_export",
        reads=_POLICY_COMMON + _EXPORT,
        writes=(
            "policy_activation_export_issuances",
            "policy_activation_export_pages",
        ),
    ),
    "policy.export.authorize": _spec(
        "authorize_policy_activation_chain_export",
        reads=_EXPORT + _CONTROL_APPROVAL,
        writes=(
            "policy_activation_export_authorizations",
            "policy_activation_export_authorization_receipts",
            "policy_activation_export_authorization_heads",
        ),
        webauthn="bound-verified-assertion-receipt",
    ),
    "policy.export.finalize": _spec(
        "finalize_policy_activation_chain_export",
        reads=_EXPORT,
        writes=(
            "policy_activation_export_attestations",
            "policy_activation_export_page_attestations",
            "policy_activation_export_authorizations",
            "policy_activation_export_authorization_receipts",
            "policy_activation_export_authorization_heads",
            "policy_runtime_evidence_verifications",
        ),
    ),
    "rbac.binding.mutate": _spec(
        "serverware_policy_authority_rbac_mutate",
        reads=(
            "rbac_authority_state",
            "rbac_role_bindings",
        )
        + _PHASE2_AGGREGATE,
        writes=(
            "metadata_audit_outbox",
            "policy_authority_transition_audits",
            "rbac_authority_state",
            "rbac_role_bindings",
        )
        + _PHASE2_AGGREGATE,
        selectors={
            "rbac_role_bindings": (
                ("arguments", "subjectId"),
            )
        },
        webauthn="bound-verified-assertion-receipt",
        proof_primitives=(
            "primary-key-row",
            "authenticated-root-delta",
            "aggregate-high-water",
            "capacity-reservation",
        ),
        maximum_query_rows=6,
        maximum_mutations=5,
        maximum_work_units=96,
    ),
    "control-approval.request": _spec(
        "ensure_control_plane_approval",
        reads=_CONTROL_APPROVAL + _PHASE2_AGGREGATE,
        writes=(
            "control_plane_approvals",
            "metadata_audit_outbox",
        )
        + _PHASE2_AGGREGATE,
        proof_primitives=(
            "primary-key-row",
            "aggregate-high-water",
            "capacity-reservation",
        ),
        maximum_query_rows=8,
        maximum_mutations=6,
        maximum_work_units=96,
    ),
    "control-approval.decide": _spec(
        "approve_control_plane_approval",
        reads=(
            _CONTROL_APPROVAL
            + _VERIFIED_APPROVAL_AUTHORITY
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            "control_plane_approvals",
            "metadata_audit_outbox",
            "webauthn_challenges",
            "webauthn_credentials",
        )
        + _PHASE2_AGGREGATE
        + _PHASE2_EVIDENCE,
        selectors={"control_plane_approvals": (("arguments", "item_id"),)},
        webauthn="bound-verified-assertion-receipt",
        approver_policy=True,
        proof_primitives=(
            "primary-key-row",
            "aggregate-high-water",
            "capacity-reservation",
            "external-evidence-receipt",
        ),
        external_evidence_types=("webauthn-hardware-authorization/v1",),
        maximum_query_rows=16,
        maximum_mutations=8,
        maximum_work_units=192,
    ),
    "control-approval.consume": _spec(
        "consume_control_plane_approval",
        reads=(
            _CONTROL_APPROVAL
            + _VERIFIED_APPROVAL_AUTHORITY
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            "control_plane_approvals",
            "metadata_audit_outbox",
        )
        + _PHASE2_AGGREGATE
        + _PHASE2_EVIDENCE,
        selectors={"control_plane_approvals": (("arguments", "item_id"),)},
        webauthn="bound-verified-assertion-receipt",
        proof_primitives=(
            "primary-key-row",
            "exact-derived-row-set",
            "aggregate-high-water",
            "capacity-reservation",
            "external-evidence-receipt",
        ),
        external_evidence_types=("webauthn-hardware-authorization/v1",),
        maximum_query_rows=12,
        maximum_mutations=8,
        maximum_work_units=128,
    ),
    "control-approval.deny": _spec(
        "deny_control_plane_approval",
        reads=(
            _CONTROL_APPROVAL
            + _VERIFIED_APPROVAL_AUTHORITY
            + ("pending_oauth_credentials",)
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            "control_plane_approvals",
            "metadata_audit_outbox",
            "pending_oauth_credentials",
        )
        + _PHASE2_AGGREGATE
        + _PHASE2_EVIDENCE,
        selectors={"control_plane_approvals": (("arguments", "item_id"),)},
        webauthn="bound-verified-assertion-receipt",
        approver_policy=True,
        proof_primitives=(
            "primary-key-row",
            "exact-derived-row-set",
            "aggregate-high-water",
            "capacity-reservation",
            "external-evidence-receipt",
        ),
        external_evidence_types=("webauthn-hardware-authorization/v1",),
        maximum_query_rows=12,
        maximum_mutations=8,
        maximum_work_units=128,
    ),
    "jit.request": _spec(
        "ensure_jit_approval_request",
        reads=(
            _APPROVAL
            + ("routes",)
            + _PHASE2_MAINTENANCE
            + _PHASE2_OPAQUE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            "approval_requests",
            "metadata_audit_outbox",
            "routes",
        )
        + _PHASE2_MAINTENANCE,
        approver_policy=True,
        proof_primitives=_PHASE2_MAINTENANCE_OPAQUE_PROOF_SET,
        external_evidence_types=("key-custody-seal/v1",),
        opaque_value_kinds=(
            "approval-review-json/v1",
            "approval-secret-json/v1",
        ),
        maximum_query_rows=24,
        maximum_mutations=140,
        maximum_work_units=1024,
    ),
    "jit.review-receipt.issue": _spec(
        "issue_approval_review_receipt",
        reads=_APPROVAL + _PHASE2_MAINTENANCE,
        writes=(
            "approval_review_receipts",
            "metadata_audit_outbox",
        )
        + _PHASE2_MAINTENANCE,
        selectors={
            "approval_requests": (
                ("arguments", "approval_request_id"),
            )
        },
        mutation_kinds={
            "approval_review_receipts": (
                "INSERT",
                "UPDATE",
                "DELETE",
            ),
            "policy_authority_bounded_aggregate_states": (
                "UPDATE",
            ),
            "policy_authority_tombstones": ("INSERT",),
            "policy_authority_work_pages": ("INSERT", "UPDATE"),
        },
        proof_primitives=_PHASE2_MAINTENANCE_PROOF_SET,
        maximum_query_rows=24,
        maximum_mutations=132,
        maximum_work_units=1024,
    ),
    "jit.decide": _spec(
        "approve_request",
        reads=(
            _APPROVAL
            + _WEBAUTHN
            + _VERIFIED_APPROVAL_AUTHORITY
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            "approval_requests",
            "approval_review_receipts",
            "approval_grants",
            "approval_request_decisions",
            "metadata_audit_outbox",
            "webauthn_challenges",
            "webauthn_credentials",
        )
        + _PHASE2_AGGREGATE
        + _PHASE2_EVIDENCE,
        selectors={"approval_requests": (("arguments", "item_id"),)},
        webauthn="bound-verified-assertion-receipt",
        approver_policy=True,
        proof_primitives=_PHASE2_EXACT_AGGREGATE_PROOF_SET
            + ("external-evidence-receipt",),
        external_evidence_types=(
            "webauthn-hardware-authorization/v1",
        ),
        maximum_query_rows=32,
        maximum_mutations=24,
        maximum_work_units=512,
    ),
    "jit.deny": _spec(
        "deny_request",
        reads=(
            _APPROVAL
            + _WEBAUTHN
            + _VERIFIED_APPROVAL_AUTHORITY
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            "approval_requests",
            "approval_review_receipts",
            "metadata_audit_outbox",
        )
        + _PHASE2_AGGREGATE
        + _PHASE2_EVIDENCE,
        selectors={"approval_requests": (("arguments", "item_id"),)},
        webauthn="bound-verified-assertion-receipt",
        approver_policy=True,
        proof_primitives=(
            "primary-key-row",
            "exact-derived-row-set",
            "aggregate-high-water",
            "capacity-reservation",
            "external-evidence-receipt",
        ),
        external_evidence_types=("webauthn-hardware-authorization/v1",),
        maximum_query_rows=24,
        maximum_mutations=12,
        maximum_work_units=256,
    ),
    "jit.consume": _spec(
        "consume_jit_grant_result",
        reads=_APPROVAL,
        writes=("approval_grants", "approval_grant_consumptions"),
    ),
    "quota.rate.consume": _spec(
        "consume_rate_limit",
        reads=(
            ("rate_limit_counters",)
            + _PHASE2_AGGREGATE
            + _PHASE2_OPAQUE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            ("rate_limit_counters",)
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        proof_primitives=(
            "primary-key-row",
            "aggregate-high-water",
            "opaque-value-receipt",
            "external-evidence-receipt",
        ),
        external_evidence_types=(
            "audit-ledger-append/v1",
            "key-custody-seal/v1",
        ),
        opaque_value_kinds=("quota-operation-recovery/v1",),
        maximum_query_rows=8,
        maximum_mutations=4,
        maximum_work_units=128,
    ),
    "quota.budget.reserve": _spec(
        "reserve_durable_budget",
        reads=_QUOTA + _PHASE2_MAINTENANCE + _PHASE2_EXACT_PAGE,
        writes=(
            "durable_budget_definitions",
            "durable_budget_events",
        )
        + _PHASE2_MAINTENANCE,
        proof_primitives=_PHASE2_MAINTENANCE_PROOF_SET,
        maximum_query_rows=32,
        maximum_mutations=140,
        maximum_work_units=1024,
    ),
    "quota.budget.dispatch": _spec(
        "mark_durable_budget_dispatched",
        reads=_QUOTA + _PHASE2_MAINTENANCE + _PHASE2_EXACT_PAGE,
        writes=(
            "durable_budget_definitions",
            "durable_budget_events",
        )
        + _PHASE2_MAINTENANCE,
        proof_primitives=_PHASE2_MAINTENANCE_PROOF_SET,
        maximum_query_rows=24,
        maximum_mutations=132,
        maximum_work_units=1024,
    ),
    "quota.budget.commit": _spec(
        "commit_durable_budget_reservation",
        reads=_QUOTA + _PHASE2_MAINTENANCE + _PHASE2_EXACT_PAGE,
        writes=(
            "durable_budget_definitions",
            "durable_budget_events",
        )
        + _PHASE2_MAINTENANCE,
        proof_primitives=_PHASE2_MAINTENANCE_PROOF_SET,
        maximum_query_rows=24,
        maximum_mutations=132,
        maximum_work_units=1024,
    ),
    "quota.budget.cancel": _spec(
        "cancel_durable_budget_reservation",
        reads=_QUOTA + _PHASE2_MAINTENANCE + _PHASE2_EXACT_PAGE,
        writes=(
            "durable_budget_definitions",
            "durable_budget_events",
        )
        + _PHASE2_MAINTENANCE,
        proof_primitives=_PHASE2_MAINTENANCE_PROOF_SET,
        maximum_query_rows=24,
        maximum_mutations=132,
        maximum_work_units=1024,
    ),
    "quota.traversal.reserve": _spec(
        "reserve_traversal_page",
        reads=_QUOTA + _PHASE2_MAINTENANCE + _PHASE2_EXACT_PAGE,
        writes=(
            "traversal_budget_chains",
            "traversal_budget_cursors",
            "traversal_budget_page_reservations",
        )
        + _PHASE2_MAINTENANCE,
        proof_primitives=_PHASE2_MAINTENANCE_PROOF_SET,
        maximum_query_rows=40,
        maximum_mutations=140,
        maximum_work_units=1280,
    ),
    "quota.traversal.dispatch": _spec(
        "mark_traversal_page_dispatched",
        reads=(
            "traversal_budget_chains",
            "traversal_budget_page_reservations",
        ),
        writes=(
            "traversal_budget_chains",
            "traversal_budget_page_reservations",
        ),
        mutation_kinds={
            "traversal_budget_chains": ("UPDATE",),
            "traversal_budget_page_reservations": ("UPDATE",),
        },
        proof_primitives=(
            "primary-key-row",
            "exact-derived-row-set",
        ),
        maximum_query_rows=2,
        maximum_mutations=2,
        maximum_work_units=20,
    ),
    "quota.traversal.complete": _spec(
        "complete_traversal_page",
        reads=(
            _QUOTA
            + _PHASE2_MAINTENANCE
            + _PHASE2_EXACT_PAGE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            "traversal_budget_chains",
            "traversal_budget_cursors",
            "traversal_budget_page_reservations",
        )
        + _PHASE2_MAINTENANCE
        + _PHASE2_EVIDENCE,
        proof_primitives=_PHASE2_MAINTENANCE_PROOF_SET
            + ("external-evidence-receipt",),
        external_evidence_types=("response-validation/v2",),
        maximum_query_rows=40,
        maximum_mutations=144,
        maximum_work_units=1536,
    ),
    "quota.traversal.terminate": _spec(
        "terminate_traversal_page",
        reads=_QUOTA,
        writes=(
            "traversal_budget_chains",
            "traversal_budget_cursors",
            "traversal_budget_page_reservations",
        ),
        mutation_kinds={
            "traversal_budget_chains": ("UPDATE",),
            "traversal_budget_cursors": ("UPDATE",),
            "traversal_budget_page_reservations": ("UPDATE",),
        },
        proof_primitives=(
            "primary-key-row",
            "exact-derived-row-set",
        ),
        maximum_query_rows=3,
        maximum_mutations=3,
        maximum_work_units=24,
    ),
    "quota.policy-state.reserve": _spec(
        "reserve_policy_state_bundle",
        reads=(
            _QUOTA
            + ("release_authorization_attempts",)
            + _PHASE2_MAINTENANCE
            + _PHASE2_EXACT_PAGE
        ),
        writes=_POLICY_STATE_WRITES + _PHASE2_MAINTENANCE,
        proof_primitives=_PHASE2_MAINTENANCE_PROOF_SET,
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=3072,
    ),
    "quota.policy-state.dispatch": _spec(
        "dispatch_policy_state_bundle",
        reads=(
            _QUOTA
            + ("release_authorization_attempts",)
            + _PHASE2_AGGREGATE
            + _PHASE2_EXACT_PAGE
        ),
        writes=_POLICY_STATE_DISPATCH_WRITES + _PHASE2_AGGREGATE,
        proof_primitives=_PHASE2_EXACT_AGGREGATE_PROOF_SET,
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=2048,
    ),
    "quota.policy-state.complete": _spec(
        "complete_policy_state_bundle",
        reads=(
            _QUOTA
            + ("release_authorization_attempts",)
            + _PHASE2_AGGREGATE
            + _PHASE2_EXACT_PAGE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            _POLICY_STATE_WRITES
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        proof_primitives=_PHASE2_EXACT_AGGREGATE_PROOF_SET
            + ("external-evidence-receipt",),
        external_evidence_types=("response-validation/v2",),
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=3072,
    ),
    "quota.policy-state.abort": _spec(
        "abort_policy_state_bundle",
        reads=_QUOTA + _PHASE2_AGGREGATE + _PHASE2_EXACT_PAGE,
        writes=_POLICY_STATE_WRITES + _PHASE2_AGGREGATE,
        proof_primitives=_PHASE2_EXACT_AGGREGATE_PROOF_SET,
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=2048,
    ),
    "quota.policy-state.fail": _spec(
        "fail_policy_state_bundle",
        reads=(
            _QUOTA
            + _PHASE2_AGGREGATE
            + _PHASE2_EXACT_PAGE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            _POLICY_STATE_WRITES
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        proof_primitives=_PHASE2_EXACT_AGGREGATE_PROOF_SET
            + ("external-evidence-receipt",),
        external_evidence_types=(
            "dispatcher-forwarding/v1",
            "response-validation/v2",
        ),
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=3072,
    ),
    "quota.policy-state.reconcile": _spec(
        "reconcile_policy_state_bundles",
        reads=(
            _QUOTA
            + ("release_authorization_attempts",)
            + _PHASE2_AGGREGATE
            + _PHASE2_EXACT_PAGE
        ),
        writes=_POLICY_STATE_WRITES + _PHASE2_AGGREGATE,
        proof_primitives=_PHASE2_EXACT_AGGREGATE_PROOF_SET,
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=4096,
    ),
    "release.reserve": _spec(
        "reserve_release_authorization_v2",
        reads=(
            _APPROVAL + _QUOTA + _RELEASE + _WEBAUTHN
            + _RELEASE_AUTHORITY + _PHASE2_RELEASE_STATE
        ),
        writes=(
            _RELEASE_RESERVE_WRITES
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        proof_primitives=_PHASE2_OPAQUE_PROOF_SET,
        external_evidence_types=("release-reservation-authority/v1",),
        opaque_value_kinds=(
            "approval-review-json/v1",
            "approval-secret-json/v1",
            "quota-operation-recovery/v1",
            "release-operation-context/v1",
        ),
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=4096,
    ),
    "release.v1.reserve": _spec(
        "reserve_release_authorization",
        reads=(
            _APPROVAL + _QUOTA + _RELEASE + _WEBAUTHN
            + _RELEASE_AUTHORITY + _PHASE2_RELEASE_STATE
        ),
        writes=(
            _RELEASE_RESERVE_WRITES
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        proof_primitives=_PHASE2_OPAQUE_PROOF_SET,
        external_evidence_types=("release-reservation-authority/v1",),
        opaque_value_kinds=(
            "approval-review-json/v1",
            "approval-secret-json/v1",
            "quota-operation-recovery/v1",
            "release-operation-context/v1",
        ),
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=3072,
    ),
    "release.dispatch": _spec(
        "dispatch_release_authorization_v2",
        reads=(
            _APPROVAL + _QUOTA + _RELEASE + _WEBAUTHN
            + _RELEASE_AUTHORITY + _PHASE2_RELEASE_STATE
        ),
        writes=(
            _RELEASE_POLICY_TRANSITION_WRITES
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        proof_primitives=_PHASE2_OPAQUE_PROOF_SET,
        external_evidence_types=("release-dispatch-authority/v1",),
        opaque_value_kinds=("quota-operation-recovery/v1",),
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=3072,
    ),
    "release.v1.dispatch": _spec(
        "dispatch_release_authorization",
        reads=(
            _APPROVAL + _QUOTA + _RELEASE + _WEBAUTHN
            + _RELEASE_AUTHORITY + _PHASE2_RELEASE_STATE
        ),
        writes=(
            _RELEASE_V1_TRANSITION_WRITES
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        proof_primitives=_PHASE2_OPAQUE_PROOF_SET,
        external_evidence_types=("release-dispatch-authority/v1",),
        opaque_value_kinds=("quota-operation-recovery/v1",),
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=2048,
    ),
    "release.complete": _spec(
        "complete_release_authorization_v2",
        reads=(
            _APPROVAL + _QUOTA + _RELEASE + _WEBAUTHN
            + _RELEASE_AUTHORITY
            + _PHASE2_RELEASE_STATE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            _RELEASE_POLICY_TRANSITION_WRITES
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        proof_primitives=_PHASE2_OPAQUE_PROOF_SET,
        external_evidence_types=(
            "response-validation/v2",
        ),
        opaque_value_kinds=("quota-operation-recovery/v1",),
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=4096,
    ),
    "release.v1.complete": _spec(
        "complete_release_authorization",
        reads=(
            _APPROVAL + _QUOTA + _RELEASE + _WEBAUTHN
            + _RELEASE_AUTHORITY
            + _PHASE2_RELEASE_STATE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            _RELEASE_V1_TRANSITION_WRITES
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        proof_primitives=_PHASE2_OPAQUE_PROOF_SET,
        external_evidence_types=("dispatcher-forwarding/v1",),
        opaque_value_kinds=("quota-operation-recovery/v1",),
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=3072,
    ),
    "release.cancel": _spec(
        "cancel_release_authorization_if_present",
        reads=(
            _APPROVAL + _QUOTA + _RELEASE + _WEBAUTHN
            + _RELEASE_AUTHORITY + _PHASE2_RELEASE_STATE
        ),
        writes=(
            _RELEASE_CANCEL_WRITES
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        proof_primitives=_PHASE2_OPAQUE_PROOF_SET,
        external_evidence_types=("release-cancellation-authority/v1",),
        opaque_value_kinds=("quota-operation-recovery/v1",),
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=2048,
    ),
    "release.reconcile": _spec(
        "reconcile_release_authorizations",
        reads=(
            _APPROVAL + _QUOTA + _RELEASE + _WEBAUTHN
            + _RELEASE_AUTHORITY + _PHASE2_RELEASE_STATE
        ),
        writes=(
            _RELEASE_POLICY_TRANSITION_WRITES
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        proof_primitives=_PHASE2_OPAQUE_PROOF_SET,
        external_evidence_types=("release-reconciliation-authority/v1",),
        opaque_value_kinds=("quota-operation-recovery/v1",),
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=4096,
    ),
    "release.credential-claim": _spec(
        "claim_release_credential_issuance",
        reads=(
            _APPROVAL + _QUOTA + _RELEASE + _WEBAUTHN
            + _RELEASE_AUTHORITY
            + _PHASE2_RELEASE_STATE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            _RELEASE_CREDENTIAL_CLAIM_WRITES
            + _PHASE2_AGGREGATE
            + _PHASE2_EVIDENCE
        ),
        proof_primitives=_PHASE2_OPAQUE_PROOF_SET,
        external_evidence_types=("credential-issuer/v1",),
        opaque_value_kinds=(
            "quota-operation-recovery/v1",
            "release-operation-context/v1",
        ),
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=4096,
    ),
    "release.audit-drain": _spec(
        "drain_release_authorization_audit_outbox",
        reads=(
            _RELEASE
            + ("approval_grant_consumptions",)
            + _PHASE2_EXACT_PAGE
            + _PHASE2_EVIDENCE
        ),
        writes=(
            "release_authorization_events",
            "approval_grant_consumptions",
        )
        + _PHASE2_EVIDENCE,
        proof_primitives=(
            "primary-key-row",
            "ordered-exact-page",
            "exact-derived-row-set",
            "external-evidence-receipt",
        ),
        external_evidence_types=("audit-ledger-append/v1",),
        maximum_query_rows=64,
        maximum_mutations=256,
        maximum_work_units=4096,
    ),
    "credential-nonce.reserve": _spec(
        "reserve_credential_lease_nonce",
        reads=(
            "credential_lease_nonces",
            "credential_lease_replay_state",
        )
        + _PHASE2_MAINTENANCE
        + _PHASE2_EXACT_PAGE,
        writes=(
            "credential_lease_nonces",
            "credential_lease_replay_state",
        )
        + _PHASE2_MAINTENANCE,
        mutation_kinds={
            "credential_lease_nonces": (
                "INSERT",
                "UPDATE",
                "DELETE",
            ),
            "credential_lease_replay_state": ("INSERT", "UPDATE"),
            "policy_authority_bounded_aggregate_states": (
                "UPDATE",
            ),
            "policy_authority_tombstones": ("INSERT",),
            "policy_authority_work_pages": ("INSERT", "UPDATE"),
        },
        proof_primitives=_PHASE2_MAINTENANCE_PROOF_SET,
        maximum_query_rows=64,
        maximum_mutations=132,
        maximum_work_units=1024,
    ),
    "webauthn.trust.stage": _spec(
        "stage_webauthn_trust_publication",
        reads=(
            "webauthn_trust_publications",
            "webauthn_trust_publication_high_water",
            "webauthn_credentials",
            "webauthn_challenges",
            "oidc_browser_sessions",
            "approval_grants",
            "control_plane_approvals",
            "rbac_role_bindings",
            "metadata_audit_outbox",
        ),
        writes=(
            "webauthn_trust_publications",
            "webauthn_credentials",
            "webauthn_challenges",
            "oidc_browser_sessions",
            "approval_grants",
            "control_plane_approvals",
            "metadata_audit_outbox",
            "policy_authority_bounded_aggregate_states",
        ),
        mutation_kinds={
            "webauthn_trust_publications": ("INSERT",),
            "webauthn_credentials": ("UPDATE",),
            "webauthn_challenges": ("UPDATE",),
            "oidc_browser_sessions": ("UPDATE",),
            "approval_grants": ("UPDATE",),
            "control_plane_approvals": ("UPDATE",),
            "metadata_audit_outbox": ("INSERT",),
            "policy_authority_bounded_aggregate_states": ("UPDATE",),
        },
        webauthn="bound-verified-assertion-receipt",
        approver_policy=True,
        proof_primitives=(
            "primary-key-row",
            "aggregate-high-water",
            authority_complete_query.PROOF_PRIMITIVE,
        ),
        maximum_query_rows=192,
        maximum_mutations=136,
        maximum_work_units=2048,
    ),
    "webauthn.trust.installation.admit": _spec(
        "admit_webauthn_trust_installation_evidence",
        reads=(
            "webauthn_trust_publications",
            "webauthn_trust_publication_high_water",
            "policy_authority_external_evidence_receipts",
        ),
        writes=("policy_authority_external_evidence_receipts",),
        mutation_kinds={"policy_authority_external_evidence_receipts": ("INSERT",)},
        proof_primitives=("primary-key-row", "aggregate-high-water", "external-evidence-receipt"),
        external_evidence_types=("webauthn-trust-installation/v2",),
        maximum_query_rows=3,
        maximum_mutations=1,
        maximum_work_units=128,
    ),
    "webauthn.trust.complete": _spec(
        "complete_webauthn_trust_publication",
        reads=(
            "webauthn_trust_publications",
            "webauthn_trust_publication_high_water",
            "metadata_audit_outbox",
        ) + _PHASE2_EVIDENCE,
        writes=(
            "webauthn_trust_publications",
            "webauthn_trust_publication_high_water",
            "metadata_audit_outbox",
            "policy_authority_bounded_aggregate_states",
        ) + _PHASE2_EVIDENCE,
        proof_primitives=(
            "primary-key-row",
            "aggregate-high-water",
            "external-evidence-receipt",
        ),
        external_evidence_types=(
            "webauthn-trust-installation/v2",
        ),
        maximum_query_rows=4,
        maximum_mutations=4,
        maximum_work_units=128,
    ),
    "webauthn.trust.error": _spec(
        "record_webauthn_trust_publication_error",
        reads=("webauthn_trust_publications",),
        writes=("webauthn_trust_publications",),
    ),
    "webauthn.registration.create": _spec(
        "create_webauthn_credential",
        reads=_WEBAUTHN,
        writes=("webauthn_credentials", "metadata_audit_outbox",
                "policy_authority_bounded_aggregate_states"),
        proof_primitives=("primary-key-row", "aggregate-high-water"),
    ),
    "webauthn.registration.evidence.admit": _spec(
        "admit_webauthn_registration_evidence",
        reads=(
            "webauthn_challenges",
            "webauthn_trust_publications",
            "webauthn_trust_publication_high_water",
            "oidc_browser_sessions",
            "policy_authority_external_evidence_receipts",
        ),
        writes=("policy_authority_external_evidence_receipts",),
        mutation_kinds={"policy_authority_external_evidence_receipts": ("INSERT",)},
        proof_primitives=("primary-key-row", "aggregate-high-water", "external-evidence-receipt"),
        external_evidence_types=("webauthn-registration-attestation/v2",),
        maximum_query_rows=5,
        maximum_mutations=1,
        maximum_work_units=128,
    ),
    "webauthn.registration.finalize": _spec(
        "finalize_webauthn_registration",
        reads=_WEBAUTHN
        + (
            "oidc_browser_sessions",
            "webauthn_trust_publication_high_water",
        )
        + _PHASE2_EVIDENCE,
        writes=(
            "metadata_audit_outbox",
            "policy_authority_bounded_aggregate_states",
            "webauthn_credentials",
            "webauthn_challenges",
        ) + _PHASE2_EVIDENCE,
        webauthn="fresh-registration-attestation",
        proof_primitives=(
            "primary-key-row",
            "aggregate-high-water",
            authority_complete_query.PROOF_PRIMITIVE,
            "external-evidence-receipt",
        ),
        external_evidence_types=(
            "webauthn-registration-attestation/v2",
        ),
        maximum_query_rows=112,
        maximum_mutations=40,
        maximum_work_units=1024,
    ),
    "webauthn.credential.revoke": _spec(
        "revoke_webauthn_credential",
        reads=_WEBAUTHN
        + (
            "approval_grants",
            "control_plane_approvals",
            "oidc_browser_sessions",
        ),
        writes=(
            "approval_grants",
            "control_plane_approvals",
            "metadata_audit_outbox",
            "policy_authority_bounded_aggregate_states",
            "oidc_browser_sessions",
            "webauthn_credentials",
            "webauthn_challenges",
        ),
        webauthn="bound-verified-assertion-receipt",
        proof_primitives=(
            "primary-key-row",
            "aggregate-high-water",
            "ordered-exact-page",
            authority_complete_query.PROOF_PRIMITIVE,
        ),
        maximum_query_rows=192,
        maximum_mutations=136,
        maximum_work_units=2048,
    ),
    "webauthn.counter.cas": _spec(
        "compare_and_swap_webauthn_sign_count",
        reads=("webauthn_credentials",),
        writes=("webauthn_credentials",),
    ),
    "webauthn.challenge.create": _spec(
        "create_webauthn_challenge",
        reads=_WEBAUTHN,
        writes=("webauthn_challenges",),
    ),
    "webauthn.challenge.claim": _spec(
        "claim_webauthn_challenge",
        reads=_WEBAUTHN,
        writes=("webauthn_challenges",),
    ),
    "webauthn.challenge.consume": _spec(
        "mark_webauthn_challenge_used",
        reads=_WEBAUTHN,
        writes=("webauthn_challenges",),
    ),
}

OPERATION_REGISTRY = MappingProxyType(_OPERATIONS)
OPERATIONS = MappingProxyType(
    {
        operation: record.compatibility_mapping(operation)
        for operation, record in OPERATION_REGISTRY.items()
    }
)
HANDLER_TO_OPERATION = MappingProxyType(
    {
        str(spec["handler"]): operation
        for operation, spec in OPERATIONS.items()
        if not str(spec["handler"]).startswith("serverware_policy_authority_")
    }
)
SQL_HANDLER_TO_OPERATION = MappingProxyType(
    {
        record.handler: operation
        for operation, record in OPERATION_REGISTRY.items()
        if record.handler.startswith("serverware_policy_authority_")
    }
)
EXECUTOR_FUNCTION_TO_OPERATION = MappingProxyType(
    {
        _executor_function_name(operation): operation
        for operation in sorted(OPERATION_REGISTRY)
    }
)
EXECUTOR_HANDLER_TO_OPERATIONS = MappingProxyType(
    {
        function_name: (operation,)
        for function_name, operation
        in EXECUTOR_FUNCTION_TO_OPERATION.items()
    }
)
EXECUTOR_FUNCTION_SIGNATURES = tuple(
    (
        function_name,
        EXECUTOR_ARGUMENT_TYPES,
        operation,
    )
    for function_name, operation
    in EXECUTOR_FUNCTION_TO_OPERATION.items()
)
SQL_GRANT_MANIFEST = MappingProxyType(
    {
        operation: MappingProxyType(
            {
                "executorHandler": _executor_function_name(operation),
                "executorIdentityArguments":
                    EXECUTOR_ARGUMENT_TYPES,
                "businessHandler": record.handler,
                "businessSelect": record.business_reads,
                "businessMutate": record.business_writes,
                "businessReadBeforeWrite":
                    record.business_read_before_write,
                "authorizationSelect": record.authorization_reads,
                "frameworkSelect": record.framework_preconditions,
                "frameworkMutate": record.framework_writes,
                "frameworkReadBeforeWrite":
                    record.framework_read_before_write,
                "mutationTemplates":
                    _mutation_templates(
                        operation,
                        record.business_writes,
                        record.mutation_kinds,
                    ),
            }
        )
        for operation, record in OPERATION_REGISTRY.items()
    }
)


def operation_manifest() -> dict[str, Any]:
    return {
        operation: {
            "handler": spec["handler"],
            "transitionProgramId": spec["transitionProgramId"],
            "planningMode": spec["planningMode"],
            "businessReads": list(spec["businessReads"]),
            "businessWrites": list(spec["businessWrites"]),
            "businessReadBeforeWrite":
                list(spec["businessReadBeforeWrite"]),
            "authorizationReads": list(spec["authorizationReads"]),
            "frameworkPreconditions":
                list(spec["frameworkPreconditions"]),
            "frameworkWrites": list(spec["frameworkWrites"]),
            "frameworkReadBeforeWrite":
                list(spec["frameworkReadBeforeWrite"]),
            "mutationTemplates": [
                dict(template)
                for template in spec["mutationTemplates"]
            ],
            "executorFunction":
                SQL_GRANT_MANIFEST[operation]["executorHandler"],
            "executorIdentityArguments":
                list(EXECUTOR_ARGUMENT_TYPES),
            "reads": list(spec["reads"]),
            "writes": list(spec["writes"]),
            "selectors": {
                table: [list(path) for path in paths]
                for table, paths in spec["selectors"].items()
            },
            "webauthn": spec["webauthn"],
            "assertionRequired": spec["assertionRequired"],
            "approverPolicyRequired":
                spec["approverPolicyRequired"],
            "predicateClosure": spec["predicateClosure"],
            "selectorClosure": spec["selectorClosure"],
            "proofKind": spec["proofKind"],
            "proofPrimitives": list(spec["proofPrimitives"]),
            "completeIndexQueryRoles": authority_complete_query.role_manifest(operation),
            "globalAuditCapacity": spec["globalAuditCapacity"],
            "auditCapacityCounterSlotsReplaced": spec["auditCapacityCounterSlotsReplaced"],
            "auditCapacityAddsAggregateRoot": spec["auditCapacityAddsAggregateRoot"],
            "maximumBusinessQueryRows": spec["maximumBusinessQueryRows"],
            "maximumBusinessMutations": spec["maximumBusinessMutations"],
            "maximumBusinessWorkUnits": spec["maximumBusinessWorkUnits"],
            "maximumQueryRows": spec["maximumQueryRows"],
            "maximumMutations": spec["maximumMutations"],
            "maximumWorkUnits": spec["maximumWorkUnits"],
            "externalEvidenceTypes":
                list(spec["externalEvidenceTypes"]),
            "opaqueValueKinds": list(spec["opaqueValueKinds"]),
            "handlerDigest": _digest(
                "serverware.policyAuthorityHandlerContract/v1",
                {
                    "sourceRevision": SOURCE_REVISION,
                    "operation": operation,
                    "handler": spec["handler"],
                    "transitionProgramId": spec["transitionProgramId"],
                    "planningMode": spec["planningMode"],
                    "businessReads": list(spec["businessReads"]),
                    "businessWrites": list(spec["businessWrites"]),
                    "businessReadBeforeWrite":
                        list(spec["businessReadBeforeWrite"]),
                    "authorizationReads":
                        list(spec["authorizationReads"]),
                    "frameworkPreconditions":
                        list(spec["frameworkPreconditions"]),
                    "frameworkWrites":
                        list(spec["frameworkWrites"]),
                    "frameworkReadBeforeWrite":
                        list(spec["frameworkReadBeforeWrite"]),
                    "mutationTemplates": [
                        dict(template)
                        for template in spec["mutationTemplates"]
                    ],
                    "executorFunction":
                        SQL_GRANT_MANIFEST[operation][
                            "executorHandler"
                        ],
                    "executorIdentityArguments":
                        list(EXECUTOR_ARGUMENT_TYPES),
                    "reads": list(spec["reads"]),
                    "writes": list(spec["writes"]),
                    "selectors": {
                        table: [list(path) for path in paths]
                        for table, paths in spec["selectors"].items()
                    },
                    "webauthn": spec["webauthn"],
                    "assertionRequired":
                        spec["assertionRequired"],
                    "approverPolicyRequired":
                        spec["approverPolicyRequired"],
                    "proofPrimitives":
                        list(spec["proofPrimitives"]),
                    "completeIndexQueryRoles": authority_complete_query.role_manifest(operation),
                    "globalAuditCapacity": spec["globalAuditCapacity"],
                    "auditCapacityCounterSlotsReplaced": spec["auditCapacityCounterSlotsReplaced"],
                    "auditCapacityAddsAggregateRoot": spec["auditCapacityAddsAggregateRoot"],
                    "maximumBusinessQueryRows": spec["maximumBusinessQueryRows"],
                    "maximumBusinessMutations": spec["maximumBusinessMutations"],
                    "maximumBusinessWorkUnits": spec["maximumBusinessWorkUnits"],
                    "maximumQueryRows":
                        spec["maximumQueryRows"],
                    "maximumMutations":
                        spec["maximumMutations"],
                    "maximumWorkUnits":
                        spec["maximumWorkUnits"],
                    "externalEvidenceTypes":
                        list(spec["externalEvidenceTypes"]),
                    "opaqueValueKinds":
                        list(spec["opaqueValueKinds"]),
                },
            ),
        }
        for operation, spec in sorted(OPERATIONS.items())
    }


def operation_contract_document() -> dict[str, Any]:
    """Return the complete source contract, distinct from its file checksum.

    A canonical JSON artifact carries this exact document. Its ordinary file
    SHA256 measures those bytes, while the semantic operation commitment also
    frames CONTRACT_SCHEMA. Never compare those different digest identities or
    substitute the smaller operation-only dispatch map for this full document.
    The document comes from the full source tables, not a caller-selected subset.
    """
    return {
        "schema": CONTRACT_SCHEMA,
        "schemaVersion": SCHEMA_VERSION,
        "sourceRevision": SOURCE_REVISION,
        "treeDepth": TREE_DEPTH,
        "treeRadix": TREE_RADIX,
        "maxQueryProofs": MAX_QUERY_PROOFS,
        "maxSelectorsPerOperation": MAX_SELECTORS_PER_OPERATION,
        "maxProofNodes": MAX_PROOF_NODES,
        "maxMutations": MAX_MUTATIONS,
        "maxWorkUnits": MAX_WORK_UNITS,
        "maxPlanQueryRows": MAX_PLAN_QUERY_ROWS,
        "maxPlanMutations": MAX_PLAN_MUTATIONS,
        "maxPlanWorkUnits": MAX_PLAN_WORK_UNITS,
        "maxPlanSelectedBytes": MAX_PLAN_SELECTED_BYTES,
        "plannerQueryBookkeeping": dict(PLANNER_QUERY_BOOKKEEPING_CONTRACT),
        "plannerCompleteAcquisition": dict(PLANNER_COMPLETE_ACQUISITION_CONTRACT),
        "revocationRetention": dict(REVOCATION_RETENTION_CONTRACT),
        "webauthnEvidenceRetention": dict(WEBAUTHN_EVIDENCE_RETENTION_CONTRACT),
        "webauthnTransitionRetention": dict(WEBAUTHN_TRANSITION_RETENTION_CONTRACT),
        "currentRootCommitMarker": dict(CURRENT_ROOT_COMMIT_MARKER_CONTRACT),
        "revocationWriterRequestCustody": dict(REVOCATION_WRITER_REQUEST_CUSTODY_CONTRACT),
        "revocationWriterAckCustody": dict(REVOCATION_WRITER_ACK_CUSTODY_CONTRACT),
        "revocationCapabilityCustody": dict(REVOCATION_CAPABILITY_CUSTODY_CONTRACT),
        "signedRevocationPlanVerification": dict(SIGNED_REVOCATION_PLAN_CONTRACT),
        "signedRevocationPlanProduction": dict(SIGNED_REVOCATION_PRODUCTION_CONTRACT),
        "signedRevocationWireAdmission": dict(SIGNED_REVOCATION_WIRE_CONTRACT),
        "auditCapacityQueryWorkUnits": AUDIT_CAPACITY_QUERY_WORK_UNITS,
        "auditCapacityMutationWorkUnits": AUDIT_CAPACITY_MUTATION_WORK_UNITS,
        "phase2StoreTables": list(PHASE2_STORE_TABLES),
        "v9AdditionalProtectedTables": list(V9_ADDITIONAL_PROTECTED_TABLES),
        "postgresCountedStoreColumns": {
            table: list(columns)
            for table, columns in POSTGRES_COUNTED_STORE_COLUMNS.items()
        },
        "postgresCountedFunctionContracts": {
            name: {
                field: list(value) if isinstance(value, tuple) else value
                for field, value in contract.items()
            }
            for name, contract in POSTGRES_COUNTED_FUNCTION_CONTRACTS.items()
        },
        "postgresCountedMaintenance": dict(POSTGRES_COUNTED_MAINTENANCE_CONTRACT),
        "verifierReadContract": VERIFIER_READ_CONTRACT,
        "verifierReadTables": sorted(VERIFIER_READ_TABLES),
        "completionReadContract": COMPLETION_READ_CONTRACT,
        "completionReaderRole": COMPLETION_READER_ROLE,
        "completionReadTables": sorted(COMPLETION_READ_TABLES),
        "successorExecutionCustody": dict(SUCCESSOR_EXECUTION_CUSTODY_CONTRACT),
        "successorExecutionFunctionSignatures": {
            name: list(arguments) for name, arguments in SUCCESSOR_EXECUTION_FUNCTION_SIGNATURES.items()
        },
        "proofPrimitives": sorted(PROOF_PRIMITIVES),
        "capabilityIssuerFunctionSignatures": {
            function_name: list(argument_types)
            for function_name, argument_types in sorted(
                CAPABILITY_ISSUER_FUNCTION_SIGNATURES.items()
            )
        },
        "capabilityIssuerFunctionArguments": {
            function_name: list(argument_names)
            for function_name, argument_names in sorted(
                CAPABILITY_ISSUER_FUNCTION_ARGUMENTS.items()
            )
        },
        "revocationCapabilityIssuerFunctionSignatures": {
            function_name: list(argument_types)
            for function_name, argument_types in sorted(
                REVOCATION_CAPABILITY_ISSUER_FUNCTION_SIGNATURES.items()
            )
        },
        "revocationCapabilityIssuerFunctionArguments": {
            function_name: list(argument_names)
            for function_name, argument_names in sorted(
                REVOCATION_CAPABILITY_ISSUER_FUNCTION_ARGUMENTS.items()
            )
        },
        "offlineMigrationReceiptProducers": {
            contract_id: {
                "handler": spec["handler"],
                "arguments": list(spec["arguments"]),
            }
            for contract_id, spec in sorted(
                OFFLINE_MIGRATION_RECEIPT_PRODUCERS.items()
            )
        },
        "operations": operation_manifest(),
    }


OPERATION_MANIFEST_DIGEST = _digest(CONTRACT_SCHEMA, operation_contract_document())


def operation_spec(operation: str) -> Mapping[str, Any]:
    try:
        return OPERATIONS[operation]
    except KeyError as exc:
        raise ValueError("operation is not in the closed authority contract") from exc


def transition_program_id(operation: str) -> str:
    spec = operation_spec(operation)
    return str(spec["transitionProgramId"])


def _contains_business_intent(value: Any) -> bool:
    if isinstance(value, Mapping):
        return (
            "businessIntent" in value
            or any(
                _contains_business_intent(item)
                for item in value.values()
            )
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_contains_business_intent(item) for item in value)
    return False


def synthesize_business_intent(
    operation: str,
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    return _synthesize_business_intent(operation, arguments, work=None)


def _synthesize_business_intent(
    operation: str,
    arguments: Mapping[str, Any],
    *,
    work: _ValidationWork | None,
) -> dict[str, Any]:
    """The actual normalization body; a private caller may charge its work."""
    spec = operation_spec(operation)
    if work is not None:
        work.prepare_scan(arguments)
    if (
        not isinstance(arguments, Mapping)
        or _contains_business_intent(arguments)
        or any(not isinstance(key, str) for key in arguments)
        or any(
            key.startswith("_")
            or key == "authority_verifier_response"
            for key in arguments
        )
    ):
        raise ValueError(
            "business intent arguments are not a closed caller-free object"
        )
    excluded = {
        "authn",
        "authn_evidence",
        "webauthn_authorization",
    }
    if operation not in {
        "webauthn.challenge.create",
        "webauthn.challenge.consume",
    }:
        excluded.add("challenge_id")
    if work is not None:
        # Use the full source graph conservatively for the filtered shallow
        # copy; do not reproduce this exclusion recipe in an accounting caller.
        work.prepare_copy(arguments)
    closed_arguments = {
        key: value
        for key, value in sorted(arguments.items())
        if key not in excluded
    }
    if work is not None:
        work.prepare_normalization(closed_arguments)
    try:
        normalized = json.loads(
            _canonical(closed_arguments).decode("ascii")
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(
            "business intent arguments are not canonical JSON"
        ) from exc
    if not isinstance(normalized, dict):
        raise ValueError("business intent arguments are not an object")
    return {
        "schema": BUSINESS_INTENT_SCHEMA,
        "operation": operation,
        "planningAdapterId": spec["planningAdapterId"],
        "arguments": normalized,
    }


def handler_contract_digest(operation: str) -> str:
    return operation_manifest()[operation]["handlerDigest"]


def mutation_template(
    operation: str,
    template_id: str,
) -> Mapping[str, Any]:
    spec = operation_spec(operation)
    for template in spec["mutationTemplates"]:
        if template["templateId"] == template_id:
            return template
    raise ValueError(
        "mutation template is not in the operation contract"
    )


def require_exact_operation_dependencies(
    operation: str,
    *,
    reads: Any,
    writes: Any,
) -> None:
    spec = operation_spec(operation)
    if tuple(sorted(set(reads))) != spec["reads"]:
        raise ValueError("authority read dependency closure is not exact")
    if tuple(sorted(set(writes))) != spec["writes"]:
        raise ValueError("authority write dependency closure is not exact")


def require_exact_operation_contract(
    operation: str,
    *,
    business_reads: Any,
    business_writes: Any,
    authorization_reads: Any,
    framework_preconditions: Any,
    framework_writes: Any,
) -> None:
    spec = operation_spec(operation)
    supplied = {
        "businessReads": business_reads,
        "businessWrites": business_writes,
        "authorizationReads": authorization_reads,
        "frameworkPreconditions": framework_preconditions,
        "frameworkWrites": framework_writes,
    }
    for field, values in supplied.items():
        if tuple(sorted(set(values))) != spec[field]:
            raise ValueError(
                f"authority {field} dependency closure is not exact"
            )


def extract_selectors(
    operation: str,
    request: Mapping[str, Any],
) -> dict[str, tuple[str, ...]]:
    spec = operation_spec(operation)
    extracted: dict[str, tuple[str, ...]] = {}
    for table, paths in spec["selectors"].items():
        values: list[str] = []
        for path in paths:
            value: Any = request
            for component in path:
                if not isinstance(value, Mapping) or component not in value:
                    raise ValueError(
                        f"selector path {'.'.join(path)} is absent"
                    )
                value = value[component]
            if not isinstance(value, (str, int)) or isinstance(value, bool):
                raise ValueError(
                    f"selector path {'.'.join(path)} is not scalar"
                )
            values.append(str(value))
        extracted[table] = tuple(values)
    if sum(len(values) for values in extracted.values()) > MAX_SELECTORS_PER_OPERATION:
        raise ValueError("authority selector proof bound is exceeded")
    return extracted
