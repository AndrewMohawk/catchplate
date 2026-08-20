pub const POSTGRES_SCHEMA_VERSION: i32 = 1;
pub const POSTGRES_SCHEMA_NAME: &str = "response_v2_state_authority";

/// Bootstrap DDL for a fresh response-v2 authority database.
///
/// The provisioner must execute this in one transaction under a migration role
/// that is not available to any runtime service. Runtime access is granted only
/// to the state-authority role after the migration digest is pinned.
pub const BOOTSTRAP_SQL: &str = r#"
CREATE SCHEMA response_v2_state_authority;

CREATE SEQUENCE response_v2_state_authority.fence_allocation_sequence
    AS bigint MINVALUE 1 NO CYCLE;

CREATE TABLE response_v2_state_authority.schema_metadata (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    schema_version integer NOT NULL CHECK (schema_version = 1),
    migration_sha256 text NOT NULL CHECK (
        migration_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE response_v2_state_authority.provider_generations (
    generation_id text PRIMARY KEY,
    predecessor_generation_id text NULL,
    status text NOT NULL CHECK (
        status IN (
            'PROVISIONED', 'RECONCILING', 'READY',
            'QUARANTINED', 'RETIRED'
        )
    ),
    fault_domain_id text NOT NULL CHECK (fault_domain_id = 'host-1'),
    quorum_profile text NOT NULL CHECK (quorum_profile = 'LOCAL_1_OF_1'),
    fault_domain_count smallint NOT NULL CHECK (fault_domain_count = 1),
    external_witness_count smallint NOT NULL CHECK (external_witness_count = 0),
    hardware_proof boolean NOT NULL CHECK (hardware_proof = false),
    attestation_mode text NOT NULL CHECK (
        attestation_mode = 'TrustedHostNoTee'
    ),
    rollback_floor bigint NOT NULL CHECK (rollback_floor >= 0),
    canonical_generation bytea NOT NULL,
    generation_sha256 text NOT NULL UNIQUE CHECK (
        generation_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    source_commit_sha256 text NOT NULL CHECK (
        source_commit_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    source_tree_sha256 text NOT NULL CHECK (
        source_tree_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    schema_bundle_sha256 text NOT NULL CHECK (
        schema_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    migration_sha256 text NOT NULL CHECK (
        migration_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    not_before_epoch_millis bigint NOT NULL CHECK (
        not_before_epoch_millis >= 0
    ),
    not_after_epoch_millis bigint NOT NULL CHECK (
        not_after_epoch_millis > not_before_epoch_millis
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (predecessor_generation_id)
        REFERENCES response_v2_state_authority.provider_generations(generation_id)
);

CREATE TABLE response_v2_state_authority.role_identities (
    generation_id text NOT NULL,
    role_id text NOT NULL,
    role_name text NOT NULL CHECK (
        role_name IN (
            'custody-router',
            'state-authority',
            'credential-transport',
            'policy-proof-verifier',
            'immutable-artifact-ledger',
            'release-attestor-publisher',
            'cleanup-watchdog'
        )
    ),
    process_id text NOT NULL,
    unix_uid integer NOT NULL CHECK (unix_uid > 0),
    unix_gid integer NOT NULL CHECK (unix_gid > 0),
    fault_domain_id text NOT NULL CHECK (fault_domain_id = 'host-1'),
    key_id text NOT NULL,
    public_key bytea NOT NULL CHECK (
        octet_length(public_key) = 32
    ),
    public_key_sha256 text NOT NULL CHECK (
        public_key_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    authority_artifact_signing boolean NOT NULL CHECK (
        authority_artifact_signing = true
    ),
    executable_sha256 text NOT NULL CHECK (
        executable_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    configuration_sha256 text NOT NULL CHECK (
        configuration_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    enabled_operations jsonb NOT NULL CHECK (
        jsonb_typeof(enabled_operations) = 'array'
        AND jsonb_array_length(enabled_operations) >= 1
        AND jsonb_array_length(enabled_operations) <= 27
    ),
    PRIMARY KEY (generation_id, role_id),
    UNIQUE (generation_id, role_name),
    UNIQUE (generation_id, process_id),
    UNIQUE (generation_id, key_id),
    FOREIGN KEY (generation_id)
        REFERENCES response_v2_state_authority.provider_generations(generation_id)
);

CREATE TABLE response_v2_state_authority.attempts (
    generation_id text NOT NULL,
    attempt_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 1),
    state text NOT NULL CHECK (
        state IN (
            'RESERVED', 'AUTHORIZED', 'STAGED', 'DISPATCHING',
            'OUTCOME_UNKNOWN', 'OBSERVED', 'RELEASE_PREPARED',
            'TERMINAL_FAILED', 'FINALIZED', 'PUBLISHED', 'ARCHIVED'
        )
    ),
    fence_token text NOT NULL,
    stable_resume_id text NOT NULL,
    owner_process_id text NOT NULL,
    owner_pid integer NOT NULL CHECK (owner_pid > 0),
    owner_start_time_ticks bigint NOT NULL CHECK (
        owner_start_time_ticks > 0
    ),
    owner_cgroup_id text NOT NULL,
    deadline_clock text NOT NULL CHECK (
        deadline_clock = 'CLOCK_BOOTTIME'
    ),
    deadline_boot_id text NOT NULL,
    deadline_boot_millis bigint NOT NULL CHECK (
        deadline_boot_millis >= 0
    ),
    request_sha256 text NOT NULL CHECK (
        request_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    route_sha256 text NOT NULL CHECK (
        route_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    credential_scope_sha256 text NOT NULL CHECK (
        credential_scope_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    terminal_code text NULL,
    terminal_detail_sha256 text NULL CHECK (
        terminal_detail_sha256 IS NULL OR
        terminal_detail_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, attempt_id),
    UNIQUE (generation_id, stable_resume_id),
    UNIQUE (generation_id, fence_token),
    FOREIGN KEY (generation_id)
        REFERENCES response_v2_state_authority.provider_generations(generation_id)
);

CREATE TABLE response_v2_state_authority.operations (
    generation_id text NOT NULL,
    operation_id text NOT NULL,
    request_id text NOT NULL,
    attempt_id text NULL,
    operation_name text NOT NULL,
    caller_role_id text NOT NULL,
    exact_request_sha256 text NOT NULL CHECK (
        exact_request_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    expected_revision bigint NULL CHECK (
        expected_revision IS NULL OR expected_revision >= 0
    ),
    expected_state text NULL,
    fence_token text NULL,
    status text NOT NULL CHECK (
        status IN ('PREPARED', 'COMMITTED', 'FAILED')
    ),
    canonical_signed_result bytea NULL,
    canonical_signed_result_sha256 text NULL CHECK (
        canonical_signed_result_sha256 IS NULL OR
        canonical_signed_result_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    result_signature jsonb NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    committed_at timestamptz NULL,
    CHECK (
        (
            operation_name IN (
                'responseV2.generation.install/v1',
                'responseV2.generation.reconcile/v1',
                'responseV2.state.query/v1'
            )
            AND attempt_id IS NULL
            AND expected_revision IS NULL
            AND expected_state IS NULL
            AND fence_token IS NULL
        )
        OR
        (
            operation_name NOT IN (
                'responseV2.generation.install/v1',
                'responseV2.generation.reconcile/v1',
                'responseV2.state.query/v1'
            )
            AND attempt_id IS NOT NULL
            AND expected_revision IS NOT NULL
            AND expected_state IS NOT NULL
            AND fence_token IS NOT NULL
        )
    ),
    PRIMARY KEY (generation_id, operation_id),
    UNIQUE (generation_id, request_id),
    FOREIGN KEY (generation_id, attempt_id)
        REFERENCES response_v2_state_authority.attempts(
            generation_id, attempt_id
        )
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (generation_id, caller_role_id)
        REFERENCES response_v2_state_authority.role_identities(
            generation_id, role_id
        )
);

CREATE TABLE response_v2_state_authority.fences (
    generation_id text NOT NULL,
    attempt_id text NOT NULL,
    fence_token text NOT NULL,
    allocation_sequence bigint NOT NULL UNIQUE,
    state text NOT NULL CHECK (
        state IN ('ACTIVE', 'REVOKED', 'QUIESCENT')
    ),
    owner_process_id text NOT NULL,
    owner_pid integer NOT NULL CHECK (owner_pid > 0),
    owner_start_time_ticks bigint NOT NULL CHECK (
        owner_start_time_ticks > 0
    ),
    owner_cgroup_id text NOT NULL,
    revoked_revision bigint NULL CHECK (revoked_revision > 0),
    owner_death_observed boolean NOT NULL DEFAULT false,
    cgroup_empty_observed boolean NOT NULL DEFAULT false,
    cgroup_death_observed boolean NOT NULL DEFAULT false,
    observation_evidence_sha256 text NULL CHECK (
        observation_evidence_sha256 IS NULL OR
        observation_evidence_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, attempt_id),
    UNIQUE (generation_id, fence_token),
    FOREIGN KEY (generation_id, attempt_id)
        REFERENCES response_v2_state_authority.attempts(
            generation_id, attempt_id
        )
);

CREATE TABLE response_v2_state_authority.replay_ledger (
    generation_id text NOT NULL,
    replay_id text NOT NULL,
    operation_id text NOT NULL,
    exact_request_sha256 text NOT NULL CHECK (
        exact_request_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    canonical_signed_result bytea NOT NULL,
    canonical_signed_result_sha256 text NOT NULL CHECK (
        canonical_signed_result_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, replay_id),
    UNIQUE (generation_id, operation_id),
    FOREIGN KEY (generation_id, operation_id)
        REFERENCES response_v2_state_authority.operations(
            generation_id, operation_id
        )
);

CREATE TABLE response_v2_state_authority.release_ledger (
    generation_id text NOT NULL,
    release_authorization_id text NOT NULL,
    attempt_id text NOT NULL,
    finalization_id text NOT NULL,
    exact_release_request_sha256 text NOT NULL CHECK (
        exact_release_request_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    inspection_result_sha256 text NOT NULL CHECK (
        inspection_result_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    release_object_sha256 text NOT NULL CHECK (
        release_object_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    client_binding_sha256 text NOT NULL CHECK (
        client_binding_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    one_use_nonce_sha256 text NOT NULL CHECK (
        one_use_nonce_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    canonical_signed_result bytea NOT NULL,
    canonical_signed_result_sha256 text NOT NULL CHECK (
        canonical_signed_result_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    prepared_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, release_authorization_id),
    FOREIGN KEY (generation_id, attempt_id)
        REFERENCES response_v2_state_authority.attempts(
            generation_id, attempt_id
        )
);

CREATE TABLE response_v2_state_authority.credential_uses (
    generation_id text NOT NULL,
    credential_use_id text NOT NULL,
    attempt_id text NOT NULL,
    credential_binding_sha256 text NOT NULL CHECK (
        credential_binding_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    transport_authorization_sha256 text NOT NULL CHECK (
        transport_authorization_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    target_effect_id text NOT NULL,
    state text NOT NULL CHECK (
        state IN (
            'DISPATCHING', 'OUTCOME_UNKNOWN',
            'OBSERVED', 'RECONCILED_FAILURE'
        )
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, credential_use_id),
    UNIQUE (generation_id, attempt_id),
    UNIQUE (generation_id, target_effect_id),
    FOREIGN KEY (generation_id, attempt_id)
        REFERENCES response_v2_state_authority.attempts(
            generation_id, attempt_id
        )
);

CREATE TABLE response_v2_state_authority.target_effects (
    generation_id text NOT NULL,
    target_effect_id text NOT NULL,
    attempt_id text NOT NULL,
    idempotency_key_sha256 text NOT NULL CHECK (
        idempotency_key_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    state text NOT NULL CHECK (
        state IN (
            'DISPATCHING', 'OUTCOME_UNKNOWN',
            'OBSERVED', 'RECONCILED_FAILURE'
        )
    ),
    request_object_sha256 text NOT NULL CHECK (
        request_object_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    response_object_sha256 text NULL CHECK (
        response_object_sha256 IS NULL OR
        response_object_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    transport_evidence_sha256 text NOT NULL CHECK (
        transport_evidence_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    uncertainty_code text NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, target_effect_id),
    UNIQUE (generation_id, attempt_id),
    UNIQUE (generation_id, idempotency_key_sha256),
    FOREIGN KEY (generation_id, attempt_id)
        REFERENCES response_v2_state_authority.attempts(
            generation_id, attempt_id
        )
);

CREATE TABLE response_v2_state_authority.policy_decisions (
    generation_id text NOT NULL,
    policy_decision_id text NOT NULL,
    attempt_id text NOT NULL,
    policy_generation_sha256 text NOT NULL CHECK (
        policy_generation_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    raw_response_object_sha256 text NULL CHECK (
        raw_response_object_sha256 IS NULL OR
        raw_response_object_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    released_projection_sha256 text NULL CHECK (
        released_projection_sha256 IS NULL OR
        released_projection_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    verifier_evidence_sha256 text NOT NULL CHECK (
        verifier_evidence_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    passed boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, policy_decision_id),
    UNIQUE (generation_id, attempt_id),
    FOREIGN KEY (generation_id, attempt_id)
        REFERENCES response_v2_state_authority.attempts(
            generation_id, attempt_id
        )
);

CREATE TABLE response_v2_state_authority.immutable_objects (
    generation_id text NOT NULL,
    object_id text NOT NULL,
    attempt_id text NOT NULL,
    object_kind text NOT NULL,
    content_sha256 text NOT NULL CHECK (
        content_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    content_length bigint NOT NULL CHECK (content_length >= 0),
    media_type text NOT NULL,
    storage_locator text NOT NULL CHECK (
        octet_length(storage_locator) BETWEEN 1 AND 1024
    ),
    immutable_storage_receipt_sha256 text NOT NULL CHECK (
        immutable_storage_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, object_id),
    UNIQUE (generation_id, content_sha256),
    FOREIGN KEY (generation_id, attempt_id)
        REFERENCES response_v2_state_authority.attempts(
            generation_id, attempt_id
        )
);

CREATE TABLE response_v2_state_authority.immutable_inspections (
    generation_id text NOT NULL,
    inspection_id text NOT NULL,
    inspection_operation_id text NOT NULL,
    attempt_id text NOT NULL,
    attempt_revision bigint NOT NULL CHECK (attempt_revision > 0),
    fence_token text NOT NULL,
    object_id text NOT NULL,
    object_kind text NOT NULL,
    object_sha256 text NOT NULL CHECK (
        object_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    object_length bigint NOT NULL CHECK (object_length >= 0),
    media_type text NOT NULL,
    immutable_storage_receipt_sha256 text NOT NULL CHECK (
        immutable_storage_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    inspection_purpose_sha256 text NOT NULL CHECK (
        inspection_purpose_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    inspected_at_boot_id text NOT NULL,
    inspected_at_boot_millis bigint NOT NULL CHECK (
        inspected_at_boot_millis >= 0
    ),
    signed_inspection_artifact bytea NOT NULL,
    inspection_artifact_sha256 text NOT NULL CHECK (
        inspection_artifact_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    canonical_signed_result bytea NOT NULL,
    canonical_signed_result_sha256 text NOT NULL CHECK (
        canonical_signed_result_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, inspection_id),
    UNIQUE (generation_id, inspection_operation_id),
    UNIQUE (generation_id, inspection_artifact_sha256),
    UNIQUE (generation_id, canonical_signed_result_sha256),
    FOREIGN KEY (generation_id, inspection_operation_id)
        REFERENCES response_v2_state_authority.operations(
            generation_id, operation_id
        ),
    FOREIGN KEY (generation_id, attempt_id)
        REFERENCES response_v2_state_authority.attempts(
            generation_id, attempt_id
        ),
    FOREIGN KEY (generation_id, object_id)
        REFERENCES response_v2_state_authority.immutable_objects(
            generation_id, object_id
        )
);

CREATE TABLE response_v2_state_authority.evidence (
    generation_id text NOT NULL,
    evidence_id text NOT NULL,
    attempt_id text NOT NULL,
    evidence_type text NOT NULL,
    producing_role_id text NOT NULL,
    canonical_artifact bytea NOT NULL,
    canonical_artifact_sha256 text NOT NULL CHECK (
        canonical_artifact_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    object_sha256 text NULL CHECK (
        object_sha256 IS NULL OR
        object_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, evidence_id),
    UNIQUE (generation_id, canonical_artifact_sha256),
    FOREIGN KEY (generation_id, attempt_id)
        REFERENCES response_v2_state_authority.attempts(
            generation_id, attempt_id
        ),
    FOREIGN KEY (generation_id, producing_role_id)
        REFERENCES response_v2_state_authority.role_identities(
            generation_id, role_id
        )
);

CREATE TABLE response_v2_state_authority.finalizations (
    generation_id text NOT NULL,
    finalization_id text NOT NULL,
    attempt_id text NOT NULL,
    attempt_revision bigint NOT NULL CHECK (attempt_revision > 0),
    fence_token text NOT NULL,
    canonical_final_envelope bytea NOT NULL,
    canonical_final_envelope_sha256 text NOT NULL CHECK (
        canonical_final_envelope_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    inspection_result_sha256 text NOT NULL CHECK (
        inspection_result_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    transition_chain_sha256 text NOT NULL CHECK (
        transition_chain_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    evidence_root_sha256 text NOT NULL CHECK (
        evidence_root_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, finalization_id),
    UNIQUE (generation_id, attempt_id),
    UNIQUE (generation_id, canonical_final_envelope_sha256),
    FOREIGN KEY (generation_id, attempt_id)
        REFERENCES response_v2_state_authority.attempts(
            generation_id, attempt_id
        ),
    FOREIGN KEY (generation_id, inspection_result_sha256)
        REFERENCES response_v2_state_authority.immutable_inspections(
            generation_id, canonical_signed_result_sha256
        )
);

ALTER TABLE response_v2_state_authority.release_ledger
ADD CONSTRAINT release_ledger_finalization_fk
FOREIGN KEY (generation_id, finalization_id)
REFERENCES response_v2_state_authority.finalizations(
    generation_id, finalization_id
);

ALTER TABLE response_v2_state_authority.release_ledger
ADD CONSTRAINT release_ledger_inspection_fk
FOREIGN KEY (generation_id, inspection_result_sha256)
REFERENCES response_v2_state_authority.immutable_inspections(
    generation_id, canonical_signed_result_sha256
);

CREATE TABLE response_v2_state_authority.archives (
    generation_id text NOT NULL,
    archive_id text NOT NULL,
    attempt_id text NOT NULL,
    finalization_id text NOT NULL,
    canonical_archive_sha256 text NOT NULL CHECK (
        canonical_archive_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    object_ids jsonb NOT NULL CHECK (jsonb_typeof(object_ids) = 'array'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, archive_id),
    UNIQUE (generation_id, attempt_id),
    FOREIGN KEY (generation_id, finalization_id)
        REFERENCES response_v2_state_authority.finalizations(
            generation_id, finalization_id
        )
);

CREATE TABLE response_v2_state_authority.publisher_outbox (
    generation_id text NOT NULL,
    outbox_id text NOT NULL,
    attempt_id text NOT NULL,
    publication_id text NOT NULL,
    finalization_id text NOT NULL,
    payload_object_sha256 text NOT NULL CHECK (
        payload_object_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    state text NOT NULL CHECK (
        state IN (
            'PENDING', 'DELIVERING', 'DELIVERED', 'OUTCOME_UNKNOWN'
        )
    ),
    delivery_attempt integer NOT NULL DEFAULT 0 CHECK (
        delivery_attempt >= 0
    ),
    exact_delivery_receipt_sha256 text NULL CHECK (
        exact_delivery_receipt_sha256 IS NULL OR
        exact_delivery_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, outbox_id),
    UNIQUE (generation_id, publication_id),
    FOREIGN KEY (generation_id, attempt_id)
        REFERENCES response_v2_state_authority.attempts(
            generation_id, attempt_id
        ),
    FOREIGN KEY (generation_id, finalization_id)
        REFERENCES response_v2_state_authority.finalizations(
            generation_id, finalization_id
        )
);

CREATE TABLE response_v2_state_authority.transparency_leaves (
    generation_id text NOT NULL,
    leaf_sequence bigint NOT NULL,
    leaf_sha256 text NOT NULL CHECK (
        leaf_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    predecessor_leaf_sha256 text NULL CHECK (
        predecessor_leaf_sha256 IS NULL OR
        predecessor_leaf_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    canonical_artifact_sha256 text NOT NULL CHECK (
        canonical_artifact_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    canonical_artifact bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, leaf_sequence),
    UNIQUE (generation_id, leaf_sha256),
    UNIQUE (generation_id, canonical_artifact_sha256),
    FOREIGN KEY (generation_id)
        REFERENCES response_v2_state_authority.provider_generations(generation_id)
);

CREATE TABLE response_v2_state_authority.transparency_checkpoints (
    generation_id text NOT NULL,
    checkpoint_id text NOT NULL,
    tree_size bigint NOT NULL CHECK (tree_size > 0),
    root_sha256 text NOT NULL CHECK (
        root_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    predecessor_checkpoint_sha256 text NULL CHECK (
        predecessor_checkpoint_sha256 IS NULL OR
        predecessor_checkpoint_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    canonical_signed_checkpoint bytea NOT NULL,
    signed_checkpoint_sha256 text NOT NULL CHECK (
        signed_checkpoint_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, checkpoint_id),
    UNIQUE (generation_id, tree_size),
    UNIQUE (generation_id, signed_checkpoint_sha256),
    FOREIGN KEY (generation_id)
        REFERENCES response_v2_state_authority.provider_generations(generation_id)
);

CREATE TABLE response_v2_state_authority.trusted_time_highwater (
    generation_id text NOT NULL,
    clock_id text NOT NULL,
    epoch_millis bigint NOT NULL CHECK (epoch_millis >= 0),
    sequence bigint NOT NULL CHECK (sequence > 0),
    source_evidence_sha256 text NOT NULL CHECK (
        source_evidence_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, clock_id),
    FOREIGN KEY (generation_id)
        REFERENCES response_v2_state_authority.provider_generations(generation_id)
);

CREATE TABLE response_v2_state_authority.reconciliation_jobs (
    generation_id text NOT NULL,
    reconciliation_job_id text NOT NULL,
    attempt_id text NULL,
    domain text NOT NULL CHECK (
        domain IN (
            'PROVIDER_GENERATIONS', 'ROLE_IDENTITIES',
            'ATTEMPTS', 'OPERATIONS', 'FENCES', 'REPLAY_LEDGERS',
            'RELEASE_LEDGERS',
            'CREDENTIAL_USES', 'POLICY_DECISIONS', 'EVIDENCE',
            'TARGET_EFFECTS', 'FINALIZATIONS', 'IMMUTABLE_OBJECTS',
            'IMMUTABLE_INSPECTIONS', 'TERMINAL_SETTLEMENTS',
            'ARCHIVES', 'PUBLISHER_OUTBOX', 'TRANSPARENCY_LEAVES',
            'TRANSPARENCY_CHECKPOINTS', 'TRUSTED_TIME_HIGHWATER'
        )
    ),
    state text NOT NULL CHECK (
        state IN ('PENDING', 'RUNNING', 'BLOCKED', 'COMPLETE', 'FAILED')
    ),
    authoritative_cursor bigint NOT NULL CHECK (
        authoritative_cursor >= 0
    ),
    blocker_code text NULL,
    result_sha256 text NULL CHECK (
        result_sha256 IS NULL OR
        result_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, reconciliation_job_id),
    UNIQUE (generation_id, domain),
    FOREIGN KEY (generation_id, attempt_id)
        REFERENCES response_v2_state_authority.attempts(
            generation_id, attempt_id
        )
);

CREATE FUNCTION response_v2_state_authority.reject_immutable_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'immutable response-v2 authority record';
END;
$$;

CREATE FUNCTION response_v2_state_authority.protect_terminal_operation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status IN ('COMMITTED', 'FAILED') THEN
        RAISE EXCEPTION 'terminal response-v2 operation is immutable';
    END IF;
    IF NEW.status NOT IN ('COMMITTED', 'FAILED') OR
       NEW.canonical_signed_result IS NULL OR
       NEW.canonical_signed_result_sha256 IS NULL OR
       NEW.result_signature IS NULL OR
       NEW.committed_at IS NULL THEN
        RAISE EXCEPTION 'operation terminalization is incomplete';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION response_v2_state_authority.protect_attempt_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state IN ('TERMINAL_FAILED', 'ARCHIVED') THEN
        RAISE EXCEPTION 'terminal response-v2 attempt is immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'attempt revision must advance exactly once';
    END IF;
    IF NEW.state = 'TERMINAL_FAILED' AND (
        NEW.terminal_code IS NULL OR
        NEW.terminal_detail_sha256 IS NULL
    ) THEN
        RAISE EXCEPTION 'terminal failure metadata is incomplete';
    END IF;
    IF NEW.state <> 'TERMINAL_FAILED' AND (
        NEW.terminal_code IS NOT NULL OR
        NEW.terminal_detail_sha256 IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'nonterminal attempt carries terminal metadata';
    END IF;
    IF ROW(
        NEW.generation_id, NEW.attempt_id, NEW.fence_token,
        NEW.stable_resume_id, NEW.owner_process_id, NEW.owner_pid,
        NEW.owner_start_time_ticks, NEW.owner_cgroup_id,
        NEW.deadline_clock, NEW.deadline_boot_id,
        NEW.deadline_boot_millis, NEW.request_sha256,
        NEW.route_sha256, NEW.credential_scope_sha256, NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.generation_id, OLD.attempt_id, OLD.fence_token,
        OLD.stable_resume_id, OLD.owner_process_id, OLD.owner_pid,
        OLD.owner_start_time_ticks, OLD.owner_cgroup_id,
        OLD.deadline_clock, OLD.deadline_boot_id,
        OLD.deadline_boot_millis, OLD.request_sha256,
        OLD.route_sha256, OLD.credential_scope_sha256, OLD.created_at
    ) THEN
        RAISE EXCEPTION 'immutable attempt identity changed';
    END IF;
    IF NEW.state = OLD.state THEN
        RETURN NEW;
    END IF;
    IF NOT (
        (OLD.state = 'RESERVED' AND NEW.state IN (
            'AUTHORIZED', 'TERMINAL_FAILED'
        ))
        OR (OLD.state = 'AUTHORIZED' AND NEW.state IN (
            'STAGED', 'TERMINAL_FAILED'
        ))
        OR (OLD.state = 'STAGED' AND NEW.state IN (
            'DISPATCHING', 'TERMINAL_FAILED'
        ))
        OR (OLD.state = 'DISPATCHING' AND NEW.state IN (
            'OBSERVED', 'OUTCOME_UNKNOWN', 'TERMINAL_FAILED'
        ))
        OR (OLD.state = 'OUTCOME_UNKNOWN' AND NEW.state IN (
            'OBSERVED', 'TERMINAL_FAILED'
        ))
        OR (OLD.state = 'OBSERVED' AND NEW.state IN (
            'RELEASE_PREPARED', 'TERMINAL_FAILED'
        ))
        OR (OLD.state = 'RELEASE_PREPARED' AND NEW.state IN (
            'FINALIZED', 'TERMINAL_FAILED'
        ))
        OR (OLD.state = 'FINALIZED' AND NEW.state IN (
            'PUBLISHED', 'TERMINAL_FAILED'
        ))
        OR (OLD.state = 'PUBLISHED' AND NEW.state IN (
            'ARCHIVED', 'TERMINAL_FAILED'
        ))
    ) THEN
        RAISE EXCEPTION 'invalid response-v2 attempt transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION response_v2_state_authority.protect_generation_manifest()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    requested_status text;
BEGIN
    requested_status := NEW.status;
    NEW.status := OLD.status;
    IF NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'provider generation manifest is immutable';
    END IF;
    NEW.status := requested_status;
    RETURN NEW;
END;
$$;

CREATE TRIGGER provider_generations_update_guard
BEFORE UPDATE ON response_v2_state_authority.provider_generations
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.protect_generation_manifest();

CREATE TRIGGER attempts_lifecycle_guard
BEFORE UPDATE ON response_v2_state_authority.attempts
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.protect_attempt_lifecycle();

CREATE TRIGGER attempts_delete_guard
BEFORE DELETE ON response_v2_state_authority.attempts
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.reject_immutable_mutation();

CREATE TRIGGER provider_generations_delete_guard
BEFORE DELETE ON response_v2_state_authority.provider_generations
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.reject_immutable_mutation();

CREATE TRIGGER role_identities_guard
BEFORE UPDATE OR DELETE ON response_v2_state_authority.role_identities
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.reject_immutable_mutation();

CREATE TRIGGER operations_update_guard
BEFORE UPDATE ON response_v2_state_authority.operations
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.protect_terminal_operation();

CREATE TRIGGER operations_delete_guard
BEFORE DELETE ON response_v2_state_authority.operations
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.reject_immutable_mutation();

CREATE TRIGGER immutable_objects_guard
BEFORE UPDATE OR DELETE ON response_v2_state_authority.immutable_objects
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.reject_immutable_mutation();

CREATE TRIGGER immutable_inspections_guard
BEFORE UPDATE OR DELETE ON response_v2_state_authority.immutable_inspections
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.reject_immutable_mutation();

CREATE TRIGGER replay_ledger_guard
BEFORE UPDATE OR DELETE ON response_v2_state_authority.replay_ledger
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.reject_immutable_mutation();

CREATE TRIGGER release_ledger_guard
BEFORE UPDATE OR DELETE ON response_v2_state_authority.release_ledger
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.reject_immutable_mutation();

CREATE TRIGGER evidence_guard
BEFORE UPDATE OR DELETE ON response_v2_state_authority.evidence
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.reject_immutable_mutation();

CREATE TRIGGER finalizations_guard
BEFORE UPDATE OR DELETE ON response_v2_state_authority.finalizations
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.reject_immutable_mutation();

CREATE TRIGGER archives_guard
BEFORE UPDATE OR DELETE ON response_v2_state_authority.archives
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.reject_immutable_mutation();

CREATE TRIGGER transparency_leaves_guard
BEFORE UPDATE OR DELETE ON response_v2_state_authority.transparency_leaves
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.reject_immutable_mutation();

CREATE TRIGGER transparency_checkpoints_guard
BEFORE UPDATE OR DELETE ON response_v2_state_authority.transparency_checkpoints
FOR EACH ROW EXECUTE FUNCTION
response_v2_state_authority.reject_immutable_mutation();

CREATE INDEX operations_attempt_idx
ON response_v2_state_authority.operations(
    generation_id, attempt_id, created_at
);
CREATE INDEX objects_attempt_idx
ON response_v2_state_authority.immutable_objects(
    generation_id, attempt_id, committed_at
);
CREATE INDEX inspections_attempt_idx
ON response_v2_state_authority.immutable_inspections(
    generation_id, attempt_id, created_at
);
CREATE INDEX outbox_pending_idx
ON response_v2_state_authority.publisher_outbox(
    generation_id, state, updated_at
);
CREATE INDEX effects_nonterminal_idx
ON response_v2_state_authority.target_effects(
    generation_id, state, updated_at
);
CREATE INDEX reconciliation_state_idx
ON response_v2_state_authority.reconciliation_jobs(
    generation_id, state, updated_at
);

REVOKE ALL ON SCHEMA response_v2_state_authority FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA response_v2_state_authority FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA response_v2_state_authority FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA response_v2_state_authority FROM PUBLIC;
"#;
