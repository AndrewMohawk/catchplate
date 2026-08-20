//! Fixed PostgreSQL statements used by the authority engine.
//!
//! Lock order is always:
//! provider generation, caller role, attempt, operation, fence, then
//! operation-specific rows sorted by their canonical primary key.

pub const CONFIGURE_TRANSACTION_SQL: &str = r#"
SELECT
    set_config('synchronous_commit', 'on', true),
    set_config('statement_timeout', $1, true),
    set_config('lock_timeout', $2, true),
    set_config('idle_in_transaction_session_timeout', $3, true)
"#;

pub const LOCK_SCHEMA_METADATA_SQL: &str = r#"
SELECT schema_version, migration_sha256
FROM response_v2_state_authority.schema_metadata
WHERE singleton = true
FOR SHARE
"#;

pub const INSERT_SCHEMA_METADATA_SQL: &str = r#"
INSERT INTO response_v2_state_authority.schema_metadata (
    singleton, schema_version, migration_sha256
) VALUES (true, $1, $2)
"#;

pub const INSERT_GENERATION_SQL: &str = r#"
INSERT INTO response_v2_state_authority.provider_generations (
    generation_id, predecessor_generation_id, status, fault_domain_id,
    quorum_profile, fault_domain_count, external_witness_count,
    hardware_proof, attestation_mode, rollback_floor,
    canonical_generation, generation_sha256, source_commit_sha256,
    source_tree_sha256, schema_bundle_sha256, migration_sha256,
    not_before_epoch_millis, not_after_epoch_millis
) VALUES (
    $1, $2, 'RECONCILING', 'host-1', 'LOCAL_1_OF_1', 1, 0, false,
    'TrustedHostNoTee', $3, $4, $5, $6, $7, $8, $9, $10, $11
)
"#;

pub const INSERT_ROLE_IDENTITY_SQL: &str = r#"
INSERT INTO response_v2_state_authority.role_identities (
    generation_id, role_id, role_name, process_id, unix_uid, unix_gid,
    fault_domain_id, key_id, public_key, public_key_sha256,
    authority_artifact_signing, executable_sha256,
    configuration_sha256, enabled_operations
) VALUES (
    $1, $2, $3, $4, $5, $6, 'host-1', $7, $8, $9, $10, $11, $12, $13
)
"#;

pub const INSERT_GENERATION_OPERATION_SQL: &str = r#"
INSERT INTO response_v2_state_authority.operations (
    generation_id, operation_id, request_id, attempt_id, operation_name,
    caller_role_id, exact_request_sha256, expected_revision, expected_state,
    fence_token, status
) VALUES (
    $1, $2, $3, NULL, $4, $5, $6, NULL, NULL, NULL, 'PREPARED'
)
"#;

pub const INSERT_RECONCILIATION_DOMAIN_SQL: &str = r#"
INSERT INTO response_v2_state_authority.reconciliation_jobs (
    generation_id, reconciliation_job_id, attempt_id, domain, state,
    authoritative_cursor, blocker_code, result_sha256
) VALUES ($1, $2, NULL, $3, 'PENDING', 0, NULL, NULL)
"#;

pub const LOCK_GENERATION_SQL: &str = r#"
SELECT canonical_generation, generation_sha256, status
FROM response_v2_state_authority.provider_generations
WHERE generation_id = $1
FOR UPDATE
"#;

pub const LOCK_RECONCILIATION_DOMAIN_SQL: &str = r#"
SELECT reconciliation_job_id, state, authoritative_cursor,
       blocker_code, result_sha256
FROM response_v2_state_authority.reconciliation_jobs
WHERE generation_id = $1 AND domain = $2
FOR UPDATE
"#;

pub const UPDATE_GENERATION_RECONCILIATION_SQL: &str = r#"
UPDATE response_v2_state_authority.reconciliation_jobs
SET reconciliation_job_id = $3,
    state = $5,
    authoritative_cursor = $6,
    blocker_code = $7,
    result_sha256 = $8,
    updated_at = clock_timestamp()
WHERE generation_id = $1
  AND domain = $2
  AND reconciliation_job_id = $3
  AND state = $4
  AND authoritative_cursor <= $6
"#;

pub const GENERATION_RECONCILIATION_STATUS_SQL: &str = r#"
SELECT domain, state, authoritative_cursor, blocker_code, result_sha256
FROM response_v2_state_authority.reconciliation_jobs
WHERE generation_id = $1
ORDER BY domain
FOR SHARE
"#;

pub const GENERATION_RECONCILIATION_CHECKPOINT_SQL: &str = r#"
SELECT state, authoritative_cursor
FROM response_v2_state_authority.reconciliation_jobs
WHERE generation_id = $1 AND domain = $2
FOR SHARE
"#;

pub const PROVIDER_GENERATIONS_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.provider_generations
WHERE generation_id = $1
"#;

pub const ROLE_IDENTITIES_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.role_identities
WHERE generation_id = $1
"#;

pub const OPERATIONS_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.operations
WHERE generation_id = $1 AND attempt_id IS NOT NULL
  AND operation_name <> 'responseV2.generation.ready/v1'
"#;

pub const ATTEMPTS_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.attempts
WHERE generation_id = $1
"#;

pub const REPLAY_LEDGER_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.replay_ledger AS replay
JOIN response_v2_state_authority.operations AS operation
  ON operation.generation_id = replay.generation_id
 AND operation.operation_id = replay.operation_id
WHERE replay.generation_id = $1
  AND operation.attempt_id IS NOT NULL
  AND operation.operation_name <> 'responseV2.generation.ready/v1'
"#;

pub const TERMINAL_SETTLEMENTS_RECONCILIATION_CURSOR_SQL: &str =
    REPLAY_LEDGER_RECONCILIATION_CURSOR_SQL;

pub const TARGET_EFFECTS_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.target_effects
WHERE generation_id = $1
"#;

pub const FENCES_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.fences
WHERE generation_id = $1
"#;

pub const RELEASES_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.release_ledger
WHERE generation_id = $1
"#;

pub const CREDENTIAL_USES_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.credential_uses
WHERE generation_id = $1
"#;

pub const POLICY_DECISIONS_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.policy_decisions
WHERE generation_id = $1
"#;

pub const EVIDENCE_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.evidence
WHERE generation_id = $1
"#;

pub const INSPECTIONS_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.immutable_inspections
WHERE generation_id = $1
"#;

pub const FINALIZATIONS_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.finalizations
WHERE generation_id = $1
"#;

pub const IMMUTABLE_OBJECTS_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.immutable_objects
WHERE generation_id = $1
"#;

pub const ARCHIVES_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.archives
WHERE generation_id = $1
"#;

pub const PUBLISHER_OUTBOX_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1 AS authoritative_cursor
FROM response_v2_state_authority.publisher_outbox
WHERE generation_id = $1
"#;

pub const TRANSPARENCY_LEAVES_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT count(*)::bigint + 1
       AS authoritative_cursor
FROM response_v2_state_authority.transparency_leaves AS leaf
JOIN response_v2_state_authority.operations AS operation
  ON operation.generation_id = leaf.generation_id
 AND operation.canonical_signed_result_sha256 =
     leaf.canonical_artifact_sha256
WHERE leaf.generation_id = $1
  AND operation.attempt_id IS NOT NULL
  AND operation.operation_name <> 'responseV2.generation.ready/v1'
"#;

pub const TRANSPARENCY_CHECKPOINTS_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT COALESCE(max(tree_size), 0)::bigint + 1
       AS authoritative_cursor
FROM response_v2_state_authority.transparency_checkpoints
WHERE generation_id = $1
"#;

pub const TRUSTED_TIME_RECONCILIATION_CURSOR_SQL: &str = r#"
SELECT COALESCE(max(sequence), 0)::bigint + 1
       AS authoritative_cursor
FROM response_v2_state_authority.trusted_time_highwater
WHERE generation_id = $1
"#;

pub const LOCK_NONTERMINAL_ATTEMPTS_SQL: &str = r#"
SELECT attempt_id, revision, state, fence_token, stable_resume_id,
       deadline_boot_id, deadline_boot_millis
FROM response_v2_state_authority.attempts
WHERE generation_id = $1
    AND state IN (
      'RESERVED', 'AUTHORIZED', 'STAGED', 'DISPATCHING',
      'OUTCOME_UNKNOWN', 'OBSERVED', 'RELEASE_PREPARED',
      'FINALIZED', 'PUBLISHED'
  )
ORDER BY attempt_id
FOR UPDATE
"#;

pub const TERMINALIZE_RECONCILED_EXPIRED_ATTEMPT_SQL: &str = r#"
UPDATE response_v2_state_authority.attempts
SET revision = revision + 1,
    state = 'TERMINAL_FAILED',
    terminal_code = 'DEADLINE_EXPIRED',
    terminal_detail_sha256 = $6,
    updated_at = clock_timestamp()
WHERE generation_id = $1
  AND attempt_id = $2
  AND revision = $3
  AND state = $4
  AND fence_token = $5
  AND state IN (
      'RESERVED', 'AUTHORIZED', 'STAGED', 'DISPATCHING',
      'OUTCOME_UNKNOWN', 'OBSERVED', 'RELEASE_PREPARED',
      'FINALIZED', 'PUBLISHED'
  )
"#;

pub const REVOKE_RECONCILED_EXPIRED_FENCE_SQL: &str = r#"
UPDATE response_v2_state_authority.fences
SET state = 'REVOKED',
    revoked_revision = $3,
    updated_at = clock_timestamp()
WHERE generation_id = $1
  AND attempt_id = $2
  AND state = 'ACTIVE'
"#;

pub const LOCK_ROLE_SQL: &str = r#"
SELECT role_id, role_name, process_id, unix_uid, unix_gid, fault_domain_id,
       key_id, public_key, public_key_sha256, executable_sha256,
       configuration_sha256, enabled_operations, authority_artifact_signing
FROM response_v2_state_authority.role_identities
WHERE generation_id = $1 AND role_id = $2
FOR SHARE
"#;

pub const LOCK_ATTEMPT_SQL: &str = r#"
SELECT revision, state, fence_token, stable_resume_id, owner_process_id,
       owner_pid, owner_start_time_ticks, owner_cgroup_id,
       deadline_boot_id, deadline_boot_millis
FROM response_v2_state_authority.attempts
WHERE generation_id = $1 AND attempt_id = $2
FOR UPDATE
"#;

pub const LOCK_OPERATION_SQL: &str = r#"
SELECT exact_request_sha256, status, canonical_signed_result,
       canonical_signed_result_sha256
FROM response_v2_state_authority.operations
WHERE generation_id = $1 AND operation_id = $2
FOR UPDATE
"#;

pub const LOCK_FENCE_SQL: &str = r#"
SELECT fence_token, allocation_sequence, state, owner_process_id, owner_pid,
       owner_start_time_ticks, owner_cgroup_id, revoked_revision,
       owner_death_observed, cgroup_empty_observed,
       cgroup_death_observed, observation_evidence_sha256
FROM response_v2_state_authority.fences
WHERE generation_id = $1 AND attempt_id = $2
FOR UPDATE
"#;

pub const INSERT_PREPARED_OPERATION_SQL: &str = r#"
INSERT INTO response_v2_state_authority.operations (
    generation_id, operation_id, request_id, attempt_id, operation_name,
    caller_role_id, exact_request_sha256, expected_revision, expected_state,
    fence_token, status
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'PREPARED'
)
"#;

pub const ALLOCATE_FENCE_SQL: &str = r#"
SELECT nextval(
    'response_v2_state_authority.fence_allocation_sequence'
) AS allocation_sequence
"#;

pub const INSERT_ATTEMPT_SQL: &str = r#"
INSERT INTO response_v2_state_authority.attempts (
    generation_id, attempt_id, revision, state, fence_token,
    stable_resume_id, owner_process_id, owner_pid, owner_start_time_ticks,
    owner_cgroup_id, deadline_clock, deadline_boot_id,
    deadline_boot_millis, request_sha256, route_sha256,
    credential_scope_sha256
) VALUES (
    $1, $2, 1, 'RESERVED', $3, $4, $5, $6, $7, $8,
    'CLOCK_BOOTTIME', $9, $10, $11, $12, $13
)
"#;

pub const INSERT_FENCE_SQL: &str = r#"
INSERT INTO response_v2_state_authority.fences (
    generation_id, attempt_id, fence_token, allocation_sequence, state,
    owner_process_id, owner_pid, owner_start_time_ticks, owner_cgroup_id
) VALUES (
    $1, $2, $3, $4, 'ACTIVE', $5, $6, $7, $8
)
"#;

pub const CAS_ATTEMPT_STATE_SQL: &str = r#"
UPDATE response_v2_state_authority.attempts
SET revision = revision + 1,
    state = $6,
    updated_at = clock_timestamp()
WHERE generation_id = $1
  AND attempt_id = $2
  AND revision = $3
  AND state = $4
  AND fence_token = $5
RETURNING revision, state, stable_resume_id
"#;

pub const CAS_ATTEMPT_BUMP_SQL: &str = r#"
UPDATE response_v2_state_authority.attempts
SET revision = revision + 1,
    updated_at = clock_timestamp()
WHERE generation_id = $1
  AND attempt_id = $2
  AND revision = $3
  AND state = $4
  AND fence_token = $5
RETURNING revision, state, stable_resume_id
"#;

pub const TERMINALIZE_ATTEMPT_SQL: &str = r#"
UPDATE response_v2_state_authority.attempts
SET revision = revision + 1,
    state = 'TERMINAL_FAILED',
    terminal_code = $6,
    terminal_detail_sha256 = $7,
    updated_at = clock_timestamp()
WHERE generation_id = $1
  AND attempt_id = $2
  AND revision = $3
  AND state = $4
  AND fence_token = $5
  AND state IN (
      'RESERVED', 'AUTHORIZED', 'STAGED', 'DISPATCHING',
      'OUTCOME_UNKNOWN', 'OBSERVED', 'RELEASE_PREPARED',
      'FINALIZED', 'PUBLISHED'
  )
RETURNING revision, state, stable_resume_id
"#;

pub const CREATE_MUTATION_SAVEPOINT_SQL: &str =
    "SAVEPOINT response_v2_mutation";
pub const ROLLBACK_MUTATION_SAVEPOINT_SQL: &str =
    "ROLLBACK TO SAVEPOINT response_v2_mutation";
pub const RELEASE_MUTATION_SAVEPOINT_SQL: &str =
    "RELEASE SAVEPOINT response_v2_mutation";

pub const INSERT_IMMUTABLE_OBJECT_SQL: &str = r#"
INSERT INTO response_v2_state_authority.immutable_objects (
    generation_id, object_id, attempt_id, object_kind, content_sha256,
    content_length, media_type, storage_locator,
    immutable_storage_receipt_sha256
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (generation_id, content_sha256) DO NOTHING
RETURNING object_id, content_sha256, content_length
"#;

pub const LOCK_IMMUTABLE_OBJECT_BY_DIGEST_SQL: &str = r#"
SELECT object_id, attempt_id, object_kind, content_sha256, content_length,
       media_type, storage_locator, immutable_storage_receipt_sha256
FROM response_v2_state_authority.immutable_objects
WHERE generation_id = $1 AND content_sha256 = $2
FOR SHARE
"#;

pub const LOCK_IMMUTABLE_OBJECT_WITH_CONTENT_SQL: &str = r#"
SELECT object_id, attempt_id, object_kind, content_sha256, content_length,
       media_type, storage_locator, immutable_storage_receipt_sha256
FROM response_v2_state_authority.immutable_objects
WHERE generation_id = $1 AND content_sha256 = $2
FOR SHARE
"#;

pub const LOCK_IMMUTABLE_OBJECT_BY_ID_SQL: &str = r#"
SELECT object_id, attempt_id, object_kind, content_sha256, content_length,
       media_type, storage_locator, immutable_storage_receipt_sha256
FROM response_v2_state_authority.immutable_objects
WHERE generation_id = $1 AND object_id = $2
FOR SHARE
"#;

pub const INSERT_IMMUTABLE_INSPECTION_SQL: &str = r#"
INSERT INTO response_v2_state_authority.immutable_inspections (
    generation_id, inspection_id, inspection_operation_id, attempt_id,
    attempt_revision, fence_token, object_id, object_kind, object_sha256,
    object_length, media_type, immutable_storage_receipt_sha256,
    inspection_purpose_sha256, inspected_at_boot_id, inspected_at_boot_millis,
    signed_inspection_artifact, inspection_artifact_sha256,
    canonical_signed_result, canonical_signed_result_sha256
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
    $11, $12, $13, $14, $15, $16, $17, $18, $19
)
"#;

pub const LOCK_IMMUTABLE_INSPECTION_SQL: &str = r#"
SELECT inspection_operation_id, attempt_id, object_id, object_sha256,
       inspection_id, attempt_revision, fence_token, object_kind,
       object_length, media_type, immutable_storage_receipt_sha256,
       inspection_purpose_sha256, inspected_at_boot_id,
       inspected_at_boot_millis, signed_inspection_artifact,
       inspection_artifact_sha256,
       canonical_signed_result, canonical_signed_result_sha256
FROM response_v2_state_authority.immutable_inspections
WHERE generation_id = $1 AND canonical_signed_result_sha256 = $2
FOR SHARE
"#;

pub const LOCK_IMMUTABLE_INSPECTION_BY_ARTIFACT_SQL: &str = r#"
SELECT inspection_operation_id, attempt_id, object_id, object_sha256,
       inspection_id, attempt_revision, fence_token, object_kind,
       object_length, media_type, immutable_storage_receipt_sha256,
       inspection_purpose_sha256, inspected_at_boot_id,
       inspected_at_boot_millis, signed_inspection_artifact,
       inspection_artifact_sha256,
       canonical_signed_result, canonical_signed_result_sha256
FROM response_v2_state_authority.immutable_inspections
WHERE generation_id = $1 AND inspection_artifact_sha256 = $2
FOR SHARE
"#;

pub const INSERT_POLICY_DECISION_SQL: &str = r#"
INSERT INTO response_v2_state_authority.policy_decisions (
    generation_id, policy_decision_id, attempt_id,
    policy_generation_sha256, raw_response_object_sha256,
    released_projection_sha256, verifier_evidence_sha256, passed
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (generation_id, evidence_id) DO NOTHING
"#;

pub const LOCK_EVIDENCE_BY_ID_SQL: &str = r#"
SELECT attempt_id, evidence_type, producing_role_id, canonical_artifact,
       canonical_artifact_sha256, object_sha256
FROM response_v2_state_authority.evidence
WHERE generation_id = $1 AND evidence_id = $2
FOR SHARE
"#;

pub const LOCK_POLICY_DECISION_SQL: &str = r#"
SELECT policy_decision_id, policy_generation_sha256,
       raw_response_object_sha256, released_projection_sha256,
       verifier_evidence_sha256, passed
FROM response_v2_state_authority.policy_decisions
WHERE generation_id = $1 AND policy_decision_id = $2
FOR UPDATE
"#;

pub const FINALIZE_POLICY_DECISION_SQL: &str = r#"
UPDATE response_v2_state_authority.policy_decisions
SET raw_response_object_sha256 = $3,
    released_projection_sha256 = $4,
    verifier_evidence_sha256 = $5,
    passed = true
WHERE generation_id = $1
  AND policy_decision_id = $2
  AND passed = true
  AND raw_response_object_sha256 IS NULL
  AND released_projection_sha256 IS NULL
"#;

pub const INSERT_CREDENTIAL_USE_SQL: &str = r#"
INSERT INTO response_v2_state_authority.credential_uses (
    generation_id, credential_use_id, attempt_id,
    credential_binding_sha256, transport_authorization_sha256,
    target_effect_id, state
) VALUES ($1, $2, $3, $4, $5, $6, 'DISPATCHING')
"#;

pub const INSERT_TARGET_EFFECT_SQL: &str = r#"
INSERT INTO response_v2_state_authority.target_effects (
    generation_id, target_effect_id, attempt_id, idempotency_key_sha256,
    state, request_object_sha256, transport_evidence_sha256
) VALUES ($1, $2, $3, $4, 'DISPATCHING', $5, $6)
"#;

pub const LOCK_TARGET_EFFECT_SQL: &str = r#"
SELECT target_effect_id, attempt_id, idempotency_key_sha256, state,
       request_object_sha256, response_object_sha256,
       transport_evidence_sha256
FROM response_v2_state_authority.target_effects
WHERE generation_id = $1 AND target_effect_id = $2
FOR UPDATE
"#;

pub const UPDATE_TARGET_EFFECT_SQL: &str = r#"
UPDATE response_v2_state_authority.target_effects
SET state = $3,
    response_object_sha256 = $4,
    transport_evidence_sha256 = $5,
    uncertainty_code = $6,
    updated_at = clock_timestamp()
WHERE generation_id = $1 AND target_effect_id = $2
"#;

pub const UPDATE_CREDENTIAL_USE_STATE_SQL: &str = r#"
UPDATE response_v2_state_authority.credential_uses
SET state = $3, updated_at = clock_timestamp()
WHERE generation_id = $1 AND target_effect_id = $2
"#;

pub const INSERT_EVIDENCE_SQL: &str = r#"
INSERT INTO response_v2_state_authority.evidence (
    generation_id, evidence_id, attempt_id, evidence_type,
    producing_role_id, canonical_artifact, canonical_artifact_sha256,
    object_sha256
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
"#;

pub const INSERT_FINALIZATION_SQL: &str = r#"
INSERT INTO response_v2_state_authority.finalizations (
    generation_id, finalization_id, attempt_id, attempt_revision,
    fence_token, canonical_final_envelope,
    canonical_final_envelope_sha256, inspection_result_sha256,
    transition_chain_sha256, evidence_root_sha256
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
"#;

pub const LOCK_FINALIZATION_BY_ATTEMPT_SQL: &str = r#"
SELECT finalization_id, canonical_final_envelope_sha256,
       canonical_final_envelope,
       inspection_result_sha256, transition_chain_sha256,
       evidence_root_sha256
FROM response_v2_state_authority.finalizations
WHERE generation_id = $1 AND attempt_id = $2
FOR SHARE
"#;

pub const ATTEMPT_TRANSITION_ROWS_SQL: &str = r#"
SELECT operation_id, operation_name, exact_request_sha256,
       expected_revision, expected_state, fence_token
FROM response_v2_state_authority.operations
WHERE generation_id = $1
  AND attempt_id = $2
ORDER BY expected_revision, operation_id
FOR SHARE
"#;

pub const ATTEMPT_EVIDENCE_ROWS_SQL: &str = r#"
SELECT evidence_id, evidence_type, producing_role_id,
       canonical_artifact_sha256, object_sha256
FROM response_v2_state_authority.evidence
WHERE generation_id = $1 AND attempt_id = $2
ORDER BY evidence_id
FOR SHARE
"#;

pub const INSERT_OUTBOX_SQL: &str = r#"
INSERT INTO response_v2_state_authority.publisher_outbox (
    generation_id, outbox_id, attempt_id, publication_id,
    finalization_id, payload_object_sha256, state
) VALUES ($1, $2, $3, $4, $5, $6, 'PENDING')
"#;

pub const LOCK_OUTBOX_SQL: &str = r#"
SELECT publication_id, finalization_id, payload_object_sha256, state,
       delivery_attempt
FROM response_v2_state_authority.publisher_outbox
WHERE generation_id = $1 AND outbox_id = $2
FOR UPDATE
"#;

pub const ACKNOWLEDGE_OUTBOX_SQL: &str = r#"
UPDATE response_v2_state_authority.publisher_outbox
SET state = 'DELIVERED',
    delivery_attempt = delivery_attempt + 1,
    exact_delivery_receipt_sha256 = $3,
    updated_at = clock_timestamp()
WHERE generation_id = $1
  AND outbox_id = $2
  AND state IN ('PENDING', 'DELIVERING', 'OUTCOME_UNKNOWN')
"#;

pub const LOCK_RELEASE_LEDGER_SQL: &str = r#"
SELECT attempt_id, finalization_id, exact_release_request_sha256,
       release_object_sha256, inspection_result_sha256, client_binding_sha256,
       one_use_nonce_sha256, canonical_signed_result,
       canonical_signed_result_sha256
FROM response_v2_state_authority.release_ledger
WHERE generation_id = $1 AND release_authorization_id = $2
FOR SHARE
"#;

pub const INSERT_RELEASE_LEDGER_SQL: &str = r#"
INSERT INTO response_v2_state_authority.release_ledger (
    generation_id, release_authorization_id, attempt_id,
    finalization_id, exact_release_request_sha256,
    inspection_result_sha256, release_object_sha256,
    client_binding_sha256, one_use_nonce_sha256,
    canonical_signed_result, canonical_signed_result_sha256
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
"#;

pub const INSERT_ARCHIVE_SQL: &str = r#"
INSERT INTO response_v2_state_authority.archives (
    generation_id, archive_id, attempt_id, finalization_id,
    canonical_archive_sha256, object_ids
) VALUES ($1, $2, $3, $4, $5, $6)
"#;

pub const REVOKE_FENCE_SQL: &str = r#"
UPDATE response_v2_state_authority.fences
SET state = 'REVOKED',
    revoked_revision = $3,
    updated_at = clock_timestamp()
WHERE generation_id = $1
  AND attempt_id = $2
  AND state = 'ACTIVE'
RETURNING fence_token, state
"#;

pub const OBSERVE_FENCE_QUIESCENCE_SQL: &str = r#"
UPDATE response_v2_state_authority.fences
SET state = 'QUIESCENT',
    owner_death_observed = true,
    cgroup_empty_observed = true,
    cgroup_death_observed = true,
    observation_evidence_sha256 = $7,
    updated_at = clock_timestamp()
WHERE generation_id = $1
  AND attempt_id = $2
  AND state = 'REVOKED'
  AND owner_process_id = $3
  AND owner_pid = $4
  AND owner_start_time_ticks = $5
  AND owner_cgroup_id = $6
RETURNING fence_token, state
"#;

pub const LOCK_TRUSTED_TIME_SQL: &str = r#"
SELECT epoch_millis, sequence, source_evidence_sha256
FROM response_v2_state_authority.trusted_time_highwater
WHERE generation_id = $1 AND clock_id = $2
FOR UPDATE
"#;

pub const LOCK_MAX_TRUSTED_TIME_SQL: &str = r#"
SELECT epoch_millis
FROM response_v2_state_authority.trusted_time_highwater
WHERE generation_id = $1
ORDER BY epoch_millis DESC, clock_id
LIMIT 1
FOR SHARE
"#;

pub const UPSERT_TRUSTED_TIME_SQL: &str = r#"
INSERT INTO response_v2_state_authority.trusted_time_highwater (
    generation_id, clock_id, epoch_millis, sequence,
    source_evidence_sha256
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (generation_id, clock_id) DO UPDATE
SET epoch_millis = EXCLUDED.epoch_millis,
    sequence = EXCLUDED.sequence,
    source_evidence_sha256 = EXCLUDED.source_evidence_sha256,
    updated_at = clock_timestamp()
WHERE response_v2_state_authority.trusted_time_highwater.sequence
          < EXCLUDED.sequence
  AND response_v2_state_authority.trusted_time_highwater.epoch_millis
          <= EXCLUDED.epoch_millis
"#;

pub const LOCK_LAST_TRANSPARENCY_LEAF_SQL: &str = r#"
SELECT leaf_sequence, leaf_sha256
FROM response_v2_state_authority.transparency_leaves
WHERE generation_id = $1
ORDER BY leaf_sequence DESC
LIMIT 1
FOR UPDATE
"#;

pub const INSERT_TRANSPARENCY_LEAF_SQL: &str = r#"
INSERT INTO response_v2_state_authority.transparency_leaves (
    generation_id, leaf_sequence, leaf_sha256,
    predecessor_leaf_sha256, canonical_artifact_sha256,
    canonical_artifact
) VALUES ($1, $2, $3, $4, $5, $6)
"#;

pub const INSERT_TRANSPARENCY_CHECKPOINT_SQL: &str = r#"
INSERT INTO response_v2_state_authority.transparency_checkpoints (
    generation_id, checkpoint_id, tree_size, root_sha256,
    predecessor_checkpoint_sha256, canonical_signed_checkpoint,
    signed_checkpoint_sha256
) VALUES ($1, $2, $3, $4, $5, $6, $7)
"#;

pub const LOCK_RECONCILIATION_JOB_SQL: &str = r#"
SELECT state, authoritative_cursor, blocker_code, result_sha256
FROM response_v2_state_authority.reconciliation_jobs
WHERE generation_id = $1 AND reconciliation_job_id = $2
FOR UPDATE
"#;

pub const UPSERT_RECONCILIATION_JOB_SQL: &str = r#"
INSERT INTO response_v2_state_authority.reconciliation_jobs (
    generation_id, reconciliation_job_id, attempt_id, domain, state,
    authoritative_cursor, blocker_code, result_sha256
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (generation_id, reconciliation_job_id) DO UPDATE
SET state = EXCLUDED.state,
    authoritative_cursor = EXCLUDED.authoritative_cursor,
    blocker_code = EXCLUDED.blocker_code,
    result_sha256 = EXCLUDED.result_sha256,
    updated_at = clock_timestamp()
WHERE response_v2_state_authority.reconciliation_jobs.state = $9
  AND response_v2_state_authority.reconciliation_jobs.authoritative_cursor
          <= EXCLUDED.authoritative_cursor
"#;

pub const COMMIT_OPERATION_SQL: &str = r#"
UPDATE response_v2_state_authority.operations
SET status = $3,
    canonical_signed_result = $4,
    canonical_signed_result_sha256 = $5,
    result_signature = $6,
    committed_at = clock_timestamp()
WHERE generation_id = $1
  AND operation_id = $2
  AND status = 'PREPARED'
"#;

pub const INSERT_REPLAY_RESULT_SQL: &str = r#"
INSERT INTO response_v2_state_authority.replay_ledger (
    generation_id, replay_id, operation_id, exact_request_sha256,
    canonical_signed_result, canonical_signed_result_sha256
) VALUES ($1, $2, $3, $4, $5, $6)
"#;

pub const LOCK_REPLAY_RESULT_SQL: &str = r#"
SELECT replay.operation_id, replay.exact_request_sha256,
       replay.canonical_signed_result,
       replay.canonical_signed_result_sha256,
       operation.attempt_id, operation.fence_token
FROM response_v2_state_authority.replay_ledger AS replay
JOIN response_v2_state_authority.operations AS operation
  ON operation.generation_id = replay.generation_id
 AND operation.operation_id = replay.operation_id
WHERE replay.generation_id = $1 AND replay.replay_id = $2
FOR SHARE
"#;

pub const READINESS_BLOCKERS_SQL: &str = r#"
WITH blockers AS (
    SELECT 'generation_not_reconciling' AS code
    FROM response_v2_state_authority.provider_generations
    WHERE generation_id = $1
      AND status NOT IN ('RECONCILING', 'READY')
    UNION ALL
    SELECT 'role_count_not_seven'
    WHERE (
        SELECT count(*)
        FROM response_v2_state_authority.role_identities
        WHERE generation_id = $1
    ) <> 7
    UNION ALL
    SELECT 'incomplete_reconciliation'
    WHERE (
        SELECT count(*)
        FROM response_v2_state_authority.reconciliation_jobs
        WHERE generation_id = $1
    ) <> 20
       OR EXISTS (
           SELECT 1
           FROM response_v2_state_authority.reconciliation_jobs
           WHERE generation_id = $1 AND state <> 'COMPLETE'
       )
    UNION ALL
    SELECT 'nonterminal_operation'
    WHERE EXISTS (
        SELECT 1
        FROM response_v2_state_authority.operations
        WHERE generation_id = $1
          AND status = 'PREPARED'
          AND operation_id <> $2
    )
    UNION ALL
    SELECT 'unreconciled_target_effect'
    WHERE EXISTS (
        SELECT 1
        FROM response_v2_state_authority.target_effects
        WHERE generation_id = $1
          AND state IN ('DISPATCHING', 'OUTCOME_UNKNOWN')
    )
    UNION ALL
    SELECT 'unquiesced_revoked_fence'
    WHERE EXISTS (
        SELECT 1
        FROM response_v2_state_authority.fences
        WHERE generation_id = $1 AND state = 'REVOKED'
    )
    UNION ALL
    SELECT 'undelivered_outbox'
    WHERE EXISTS (
        SELECT 1
        FROM response_v2_state_authority.publisher_outbox
        WHERE generation_id = $1
          AND state IN ('DELIVERING', 'OUTCOME_UNKNOWN')
    )
    UNION ALL
    SELECT 'missing_trusted_time'
    WHERE NOT EXISTS (
        SELECT 1
        FROM response_v2_state_authority.trusted_time_highwater
        WHERE generation_id = $1
    )
    UNION ALL
    SELECT 'missing_transparency_checkpoint'
    WHERE NOT EXISTS (
        SELECT 1
        FROM response_v2_state_authority.transparency_checkpoints
        WHERE generation_id = $1
    )
)
SELECT code FROM blockers ORDER BY code
"#;

pub const MARK_GENERATION_READY_SQL: &str = r#"
UPDATE response_v2_state_authority.provider_generations
SET status = 'READY'
WHERE generation_id = $1
  AND status = 'RECONCILING'
  AND (
      SELECT count(*)
      FROM response_v2_state_authority.reconciliation_jobs
      WHERE generation_id = $1
  ) = 20
  AND NOT EXISTS (
      SELECT 1
      FROM response_v2_state_authority.reconciliation_jobs
      WHERE generation_id = $1 AND state <> 'COMPLETE'
  )
RETURNING generation_id, status
"#;
