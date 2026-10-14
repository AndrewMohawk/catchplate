"""Pure, source-owned metadata DDL; no installation or database access."""
from __future__ import annotations

from serverware.authority_store.v9_schema_source import authority_v9_schema_source


def metadata_base_schema_source() -> str:
    return """
            CREATE TABLE IF NOT EXISTS setup_native_final_attempts (
                session_id TEXT PRIMARY KEY, revision BIGINT NOT NULL, phase TEXT NOT NULL,
                owner_id TEXT NOT NULL, reviewer_id TEXT, reviewer_credential_id TEXT, review_trust_original TEXT,
                hardware_original TEXT NOT NULL, challenge_original TEXT NOT NULL, challenge_sha256 TEXT NOT NULL UNIQUE,
                receipt_original TEXT, prepare_request_digest TEXT NOT NULL UNIQUE, prepare_audit_id TEXT NOT NULL UNIQUE,
                complete_request_digest TEXT UNIQUE, complete_audit_id TEXT UNIQUE, settle_request_digest TEXT UNIQUE,
                configuration_digest TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT, settled_at TEXT,
                CHECK (length(session_id)=36 AND length(owner_id) BETWEEN 1 AND 1024 AND length(prepare_audit_id)=36),
                CHECK (length(hardware_original) BETWEEN 2 AND 4194304 AND length(challenge_original) BETWEEN 2 AND 8192),
                CHECK (length(challenge_sha256)=71 AND length(prepare_request_digest)=71 AND length(configuration_digest)=71),
                CHECK (receipt_original IS NULL OR length(receipt_original) BETWEEN 2 AND 16384),
                CHECK (review_trust_original IS NULL OR length(review_trust_original) BETWEEN 2 AND 4096),
                CHECK ((revision=0 AND phase='final_outcome_unknown' AND reviewer_id IS NULL AND reviewer_credential_id IS NULL
                    AND review_trust_original IS NULL AND receipt_original IS NULL AND complete_request_digest IS NULL AND complete_audit_id IS NULL AND completed_at IS NULL)
                    OR (revision IN (1,2) AND reviewer_id IS NOT NULL AND reviewer_id<>owner_id AND length(reviewer_credential_id)=36
                    AND review_trust_original IS NOT NULL AND receipt_original IS NOT NULL AND length(complete_request_digest)=71 AND length(complete_audit_id)=36 AND completed_at IS NOT NULL)),
                CHECK ((revision=0 OR revision=1 AND phase='native_completion_pending_audit') AND settle_request_digest IS NULL AND settled_at IS NULL
                    OR revision=2 AND phase='native_scoped_complete' AND length(settle_request_digest)=71 AND settled_at IS NOT NULL)
            );
            CREATE TABLE IF NOT EXISTS setup_native_hardware_attempts (
                session_id TEXT PRIMARY KEY, revision BIGINT NOT NULL, phase TEXT NOT NULL, owner_id TEXT NOT NULL,
                inputs_original TEXT NOT NULL, attempt_original TEXT NOT NULL, attempt_sha256 TEXT NOT NULL UNIQUE,
                prepare_request_digest TEXT NOT NULL UNIQUE, prepare_audit_id TEXT NOT NULL UNIQUE,
                evidence_original TEXT, hardware_receipt_original TEXT, proxy_receipt_original TEXT, result_original TEXT,
                complete_request_digest TEXT UNIQUE, configuration_digest TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT,
                CHECK (length(session_id) = 36 AND length(owner_id) BETWEEN 1 AND 1024 AND length(prepare_audit_id) = 36),
                CHECK (length(attempt_sha256) = 71 AND length(prepare_request_digest) = 71 AND length(configuration_digest) = 71),
                CHECK (length(inputs_original) BETWEEN 2 AND 4194304 AND length(attempt_original) BETWEEN 2 AND 8192),
                CHECK ((revision = 0 AND phase = 'hardware_outcome_unknown' AND evidence_original IS NULL AND hardware_receipt_original IS NULL
                    AND proxy_receipt_original IS NULL AND result_original IS NULL AND complete_request_digest IS NULL AND completed_at IS NULL)
                    OR (revision = 1 AND phase = 'hardware_proxy_verified' AND evidence_original IS NOT NULL AND hardware_receipt_original IS NOT NULL
                    AND proxy_receipt_original IS NOT NULL AND result_original IS NOT NULL AND complete_request_digest IS NOT NULL AND completed_at IS NOT NULL)),
                CHECK (evidence_original IS NULL OR length(evidence_original) BETWEEN 2 AND 65536),
                CHECK (hardware_receipt_original IS NULL OR length(hardware_receipt_original) BETWEEN 2 AND 16384),
                CHECK (proxy_receipt_original IS NULL OR length(proxy_receipt_original) BETWEEN 2 AND 16384),
                CHECK (result_original IS NULL OR length(result_original) BETWEEN 2 AND 8192),
                CHECK (complete_request_digest IS NULL OR length(complete_request_digest) = 71)
            );

            CREATE TABLE IF NOT EXISTS setup_native_runtime_attempts (
                session_id TEXT PRIMARY KEY, revision BIGINT NOT NULL, phase TEXT NOT NULL, owner_id TEXT NOT NULL,
                association_sha256 TEXT NOT NULL, scope_original TEXT NOT NULL, attempt_original TEXT NOT NULL,
                attempt_sha256 TEXT NOT NULL UNIQUE, prepare_request_digest TEXT NOT NULL UNIQUE, prepare_audit_id TEXT NOT NULL UNIQUE,
                capture_original_base64url TEXT, capture_sha256 TEXT UNIQUE, result_original TEXT, complete_request_digest TEXT UNIQUE,
                configuration_digest TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT,
                CHECK (length(session_id) = 36 AND length(owner_id) BETWEEN 1 AND 1024 AND length(prepare_audit_id) = 36),
                CHECK (length(association_sha256) = 71 AND length(attempt_sha256) = 71 AND length(prepare_request_digest) = 71 AND length(configuration_digest) = 71),
                CHECK (length(scope_original) BETWEEN 2 AND 32768 AND length(attempt_original) BETWEEN 2 AND 8192),
                CHECK ((revision = 0 AND phase = 'capture_outcome_unknown' AND capture_original_base64url IS NULL AND capture_sha256 IS NULL
                    AND result_original IS NULL AND complete_request_digest IS NULL AND completed_at IS NULL)
                    OR (revision = 1 AND phase = 'runtime_evidence_recorded' AND capture_original_base64url IS NOT NULL AND capture_sha256 IS NOT NULL
                    AND result_original IS NOT NULL AND complete_request_digest IS NOT NULL AND completed_at IS NOT NULL)),
                CHECK (capture_original_base64url IS NULL OR length(capture_original_base64url) BETWEEN 1 AND 699051),
                CHECK (capture_sha256 IS NULL OR length(capture_sha256) = 71),
                CHECK (result_original IS NULL OR length(result_original) BETWEEN 2 AND 8192),
                CHECK (complete_request_digest IS NULL OR length(complete_request_digest) = 71)
            );

            CREATE TABLE IF NOT EXISTS setup_native_canary_associations (
                session_id TEXT PRIMARY KEY, revision BIGINT NOT NULL, phase TEXT NOT NULL, owner_id TEXT NOT NULL,
                setup_sha256 TEXT NOT NULL, continuation_sha256 TEXT NOT NULL, enrollment_sha256 TEXT NOT NULL,
                installation_sha256 TEXT NOT NULL, canary_id TEXT NOT NULL, finalization_sha256 TEXT NOT NULL,
                publication_sha256 TEXT NOT NULL, policy_hash TEXT NOT NULL, request_original TEXT NOT NULL,
                request_digest TEXT NOT NULL UNIQUE, configuration_digest TEXT NOT NULL, audit_event_digest TEXT NOT NULL,
                associated_at TEXT NOT NULL,
                CHECK (revision = 0 AND phase = 'canary_publication_associated'),
                CHECK (length(session_id) = 36 AND length(owner_id) BETWEEN 1 AND 1024 AND length(canary_id) BETWEEN 1 AND 256),
                CHECK (length(setup_sha256) = 71 AND length(continuation_sha256) = 71 AND length(enrollment_sha256) = 71
                    AND length(installation_sha256) = 71 AND length(finalization_sha256) = 71 AND length(publication_sha256) = 71
                    AND length(policy_hash) = 71 AND length(request_digest) = 71 AND length(configuration_digest) = 71
                    AND length(audit_event_digest) = 71),
                CHECK (length(request_original) BETWEEN 2 AND 16384)
            );

            CREATE TABLE IF NOT EXISTS setup_native_ca_installations (
                session_id TEXT PRIMARY KEY, revision BIGINT NOT NULL, phase TEXT NOT NULL, owner_id TEXT NOT NULL,
                enrollment_sha256 TEXT NOT NULL, installation_original TEXT NOT NULL, host_key_id TEXT NOT NULL,
                prepared_original TEXT NOT NULL, prepared_sha256 TEXT NOT NULL UNIQUE, prepare_request_digest TEXT NOT NULL UNIQUE,
                observation_original TEXT, observation_sha256 TEXT UNIQUE, complete_request_digest TEXT UNIQUE,
                configuration_digest TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT,
                CHECK (length(session_id) = 36 AND length(owner_id) BETWEEN 1 AND 1024),
                CHECK (length(enrollment_sha256) = 71 AND length(host_key_id) = 71 AND length(prepared_sha256) = 71
                    AND length(prepare_request_digest) = 71 AND length(configuration_digest) = 71),
                CHECK (length(installation_original) BETWEEN 1 AND 43691 AND length(prepared_original) BETWEEN 2 AND 8192),
                CHECK ((revision = 0 AND phase = 'installation_unknown' AND observation_original IS NULL AND observation_sha256 IS NULL
                    AND complete_request_digest IS NULL AND completed_at IS NULL)
                    OR (revision = 1 AND phase = 'ca_readback_authenticated' AND observation_original IS NOT NULL AND observation_sha256 IS NOT NULL
                    AND complete_request_digest IS NOT NULL AND completed_at IS NOT NULL)),
                CHECK (observation_original IS NULL OR length(observation_original) BETWEEN 2 AND 32768),
                CHECK (observation_sha256 IS NULL OR length(observation_sha256) = 71),
                CHECK (complete_request_digest IS NULL OR length(complete_request_digest) = 71)
            );

            CREATE TABLE IF NOT EXISTS setup_native_enrollments (
                session_id TEXT PRIMARY KEY, revision BIGINT NOT NULL, phase TEXT NOT NULL, owner_id TEXT NOT NULL,
                intent_original TEXT NOT NULL, intent_sha256 TEXT NOT NULL UNIQUE, approval_id TEXT NOT NULL UNIQUE,
                approval_original TEXT NOT NULL, prepare_request_digest TEXT NOT NULL UNIQUE,
                certificate_original TEXT, certificate_sha256 TEXT UNIQUE, association_original TEXT,
                complete_request_digest TEXT UNIQUE, configuration_digest TEXT NOT NULL,
                created_at TEXT NOT NULL, expires_at BIGINT NOT NULL, completed_at TEXT,
                CHECK (length(session_id) = 36 AND length(approval_id) = 36),
                CHECK (length(owner_id) BETWEEN 1 AND 1024),
                CHECK (length(intent_original) BETWEEN 2 AND 1200000),
                CHECK (length(approval_original) BETWEEN 2 AND 131072),
                CHECK (length(intent_sha256) = 71 AND length(prepare_request_digest) = 71 AND length(configuration_digest) = 71),
                CHECK (expires_at > 0),
                CHECK ((revision = 0 AND phase = 'issuance_unknown' AND certificate_original IS NULL
                    AND certificate_sha256 IS NULL AND association_original IS NULL AND complete_request_digest IS NULL AND completed_at IS NULL)
                    OR (revision = 1 AND phase = 'certificate_issued' AND certificate_original IS NOT NULL
                    AND certificate_sha256 IS NOT NULL AND association_original IS NOT NULL AND complete_request_digest IS NOT NULL AND completed_at IS NOT NULL)),
                CHECK (certificate_original IS NULL OR length(certificate_original) BETWEEN 1 AND 87382),
                CHECK (association_original IS NULL OR length(association_original) BETWEEN 2 AND 4096),
                CHECK (certificate_sha256 IS NULL OR length(certificate_sha256) = 71),
                CHECK (complete_request_digest IS NULL OR length(complete_request_digest) = 71)
            );

            CREATE TABLE IF NOT EXISTS setup_policy_continuations (
                session_id TEXT PRIMARY KEY,
                revision BIGINT NOT NULL,
                phase TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                setup_original TEXT NOT NULL,
                setup_sha256 TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                credential_version BIGINT NOT NULL,
                generation_request_id TEXT NOT NULL,
                generation_claim_sha256 TEXT NOT NULL,
                generation_publication_digest TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                canary_id TEXT NOT NULL,
                artifact_envelope_digest TEXT NOT NULL,
                assignment_envelope_digest TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                route_policy_digest TEXT NOT NULL,
                assignment_digest TEXT NOT NULL,
                request_original TEXT NOT NULL,
                request_digest TEXT NOT NULL UNIQUE,
                configuration_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                CHECK (length(session_id) = 36 AND length(credential_id) = 36 AND length(generation_request_id) = 36),
                CHECK (revision = 0 AND phase = 'candidate_bound' AND credential_version = 1),
                CHECK (length(owner_id) BETWEEN 1 AND 1024),
                CHECK (length(setup_original) BETWEEN 2 AND 65536),
                CHECK (length(request_original) BETWEEN 2 AND 2097152),
                CHECK (length(setup_sha256) = 71 AND length(generation_claim_sha256) = 71),
                CHECK (length(generation_publication_digest) = 71 AND length(artifact_envelope_digest) = 71),
                CHECK (length(assignment_envelope_digest) = 71 AND length(policy_hash) = 71),
                CHECK (length(route_policy_digest) = 71 AND length(assignment_digest) = 71),
                CHECK (length(request_digest) = 71 AND length(configuration_digest) = 71),
                CHECK (length(candidate_id) BETWEEN 1 AND 256 AND length(canary_id) BETWEEN 1 AND 256)
            );

            CREATE TABLE IF NOT EXISTS policy_canary_delivery_slots (
                id TEXT PRIMARY KEY,
                head_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                canary_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                holder_id TEXT NOT NULL,
                native_boot_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                delivery_assignment_digest TEXT NOT NULL,
                intake_assignment_digest TEXT NOT NULL,
                canary_assignment_digest TEXT NOT NULL,
                canary_boot_id TEXT NOT NULL,
                configuration_digest TEXT NOT NULL,
                http_sha256 TEXT NOT NULL UNIQUE,
                http_byte_count BIGINT NOT NULL,
                part_count BIGINT NOT NULL,
                status TEXT NOT NULL,
                prepare_request_digest TEXT NOT NULL UNIQUE,
                prepare_evidence_original TEXT NOT NULL,
                claim_request_digest TEXT UNIQUE,
                claim_evidence_original TEXT,
                prepare_completion_sha256 TEXT,
                read_completion_sha256 TEXT,
                intake_request_digest TEXT UNIQUE,
                intake_result_sha256 TEXT,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (length(id) = 36 AND length(head_id) = 71),
                CHECK (length(deployment_id) BETWEEN 1 AND 128 AND length(instance_id) BETWEEN 1 AND 128),
                CHECK (length(canary_id) BETWEEN 1 AND 256),
                CHECK (length(holder_id) = 71 AND length(native_boot_id) = 43 AND length(key_id) = 71),
                CHECK (length(delivery_assignment_digest) = 71 AND length(intake_assignment_digest) = 71),
                CHECK (length(canary_assignment_digest) = 71 AND length(canary_boot_id) = 71 AND length(configuration_digest) = 71),
                CHECK (length(http_sha256) = 71 AND http_byte_count BETWEEN 1 AND 1245184),
                CHECK (part_count BETWEEN 1 AND 20 AND part_count = (http_byte_count + 65535) / 65536),
                CHECK (status IN ('prepared', 'claimed', 'consumed')),
                CHECK (length(prepare_request_digest) = 71 AND length(prepare_evidence_original) BETWEEN 2 AND 131072),
                CHECK (claim_request_digest IS NULL OR length(claim_request_digest) = 71),
                CHECK (claim_evidence_original IS NULL OR length(claim_evidence_original) BETWEEN 2 AND 131072),
                CHECK (prepare_completion_sha256 IS NULL OR length(prepare_completion_sha256) = 71),
                CHECK (read_completion_sha256 IS NULL OR length(read_completion_sha256) = 71),
                CHECK (intake_request_digest IS NULL OR length(intake_request_digest) = 71),
                CHECK (intake_result_sha256 IS NULL OR length(intake_result_sha256) = 71),
                CHECK ((claim_request_digest IS NULL) = (status = 'prepared')),
                CHECK ((claim_evidence_original IS NULL) = (status = 'prepared')),
                CHECK ((prepare_completion_sha256 IS NULL) = (status = 'prepared')),
                CHECK ((read_completion_sha256 IS NULL) = (status = 'prepared')),
                CHECK ((intake_request_digest IS NULL) = (status <> 'consumed')),
                CHECK ((intake_result_sha256 IS NULL) = (status <> 'consumed')),
                CHECK (issued_at_epoch_ns > 0 AND expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (expires_at_epoch_ns - issued_at_epoch_ns <= 30000000000)
            );

            CREATE TABLE IF NOT EXISTS policy_canary_delivery_parts (
                slot_id TEXT NOT NULL REFERENCES policy_canary_delivery_slots(id),
                ordinal BIGINT NOT NULL,
                original TEXT NOT NULL,
                original_sha256 TEXT NOT NULL,
                PRIMARY KEY (slot_id, ordinal),
                CHECK (ordinal BETWEEN 0 AND 19),
                CHECK (length(original) BETWEEN 1 AND 65536),
                CHECK (length(original_sha256) = 71)
            );

            CREATE TABLE IF NOT EXISTS policy_canary_delivery_heads (
                id TEXT PRIMARY KEY,
                deployment_id TEXT NOT NULL,
                canary_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                sequence BIGINT NOT NULL,
                slot_id TEXT NOT NULL REFERENCES policy_canary_delivery_slots(id),
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (deployment_id, canary_id, instance_id),
                CHECK (length(id) = 71 AND sequence > 0),
                CHECK (length(deployment_id) BETWEEN 1 AND 128 AND length(instance_id) BETWEEN 1 AND 128),
                CHECK (length(canary_id) BETWEEN 1 AND 256),
                CHECK (status IN ('prepared', 'claimed', 'consumed'))
            );

            CREATE TABLE IF NOT EXISTS serverware_store_migrations (
                migration TEXT PRIMARY KEY,
                version BIGINT NOT NULL,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policy_canary_intake_batches (
                request_id TEXT PRIMARY KEY,
                canary_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                purpose_assignment_digest TEXT NOT NULL,
                canary_assignment_digest TEXT NOT NULL,
                configuration_digest TEXT NOT NULL,
                batch_sha256 TEXT NOT NULL UNIQUE,
                batch_original TEXT NOT NULL,
                native_evidence_original TEXT NOT NULL,
                request_digest TEXT NOT NULL UNIQUE,
                result_original TEXT NOT NULL,
                audit_event_digest TEXT NOT NULL UNIQUE,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                created_at TEXT NOT NULL,
                CHECK (length(request_id) = 36),
                CHECK (length(canary_id) BETWEEN 1 AND 256),
                CHECK (length(instance_id) BETWEEN 1 AND 128),
                CHECK (length(boot_id) = 71),
                CHECK (length(purpose_assignment_digest) = 71),
                CHECK (length(canary_assignment_digest) = 71),
                CHECK (length(configuration_digest) = 71),
                CHECK (length(batch_sha256) = 71),
                CHECK (length(batch_original) BETWEEN 2 AND 1048576),
                CHECK (length(native_evidence_original) BETWEEN 2 AND 131072),
                CHECK (length(request_digest) = 71),
                CHECK (length(result_original) BETWEEN 2 AND 2097152),
                CHECK (length(audit_event_digest) = 71),
                CHECK (issued_at_epoch_ns > 0),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (expires_at_epoch_ns - issued_at_epoch_ns <= 30000000000)
            );

            CREATE TABLE IF NOT EXISTS policy_shadow_generation_claims (
                request_id TEXT PRIMARY KEY,
                replay_id TEXT NOT NULL UNIQUE,
                management_handoff_id TEXT NOT NULL UNIQUE,
                actor_id TEXT NOT NULL,
                configuration_digest TEXT NOT NULL,
                context_json TEXT NOT NULL,
                management_request_json TEXT NOT NULL,
                request_identity_digest TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                request_digest TEXT NOT NULL UNIQUE,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                created_at TEXT NOT NULL,
                publication_envelope_digest TEXT UNIQUE,
                CHECK (length(request_id) = 36),
                CHECK (length(replay_id) = 71),
                CHECK (length(management_handoff_id) = 72),
                CHECK (length(context_json) BETWEEN 2 AND 8192),
                CHECK (length(management_request_json) BETWEEN 2 AND 1048576),
                CHECK (issued_at_epoch_ns > 0),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (expires_at_epoch_ns - issued_at_epoch_ns <= 30000000000),
                CHECK (length(configuration_digest) = 71),
                CHECK (length(request_identity_digest) = 71),
                CHECK (length(payload_digest) = 71),
                CHECK (length(request_digest) = 71),
                CHECK (publication_envelope_digest IS NULL OR length(publication_envelope_digest) = 71)
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                encrypted_secret TEXT NOT NULL,
                encrypted_dek TEXT,
                secret_nonce TEXT,
                secret_ciphertext TEXT,
                secret_kek_id TEXT,
                credential_version INTEGER NOT NULL DEFAULT 1,
                secret_updated_at TEXT,
                metadata TEXT NOT NULL DEFAULT '{}',
                lifecycle_status TEXT NOT NULL DEFAULT 'active',
                revocation_error TEXT,
                revocation_requested_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_oauth_credentials (
                id TEXT PRIMARY KEY,
                requester_id TEXT NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                encrypted_secret TEXT NOT NULL,
                encrypted_dek TEXT NOT NULL,
                secret_nonce TEXT NOT NULL,
                secret_ciphertext TEXT NOT NULL,
                secret_kek_id TEXT NOT NULL,
                credential_version INTEGER NOT NULL,
                secret_updated_at TEXT NOT NULL,
                metadata TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                review_json TEXT NOT NULL,
                target_credential_id TEXT,
                target_credential_version INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',
                revocation_status TEXT,
                revocation_error TEXT,
                revocation_attempts INTEGER NOT NULL DEFAULT 0,
                revocation_next_attempt_at TEXT,
                revocation_lease_owner TEXT,
                revocation_lease_until TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS pending_oauth_credentials_expiry
                ON pending_oauth_credentials (expires_at);

            CREATE TABLE IF NOT EXISTS setup_sessions (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                current_assignee_id TEXT,
                status TEXT NOT NULL,
                phase TEXT NOT NULL,
                revision BIGINT NOT NULL,
                template_id TEXT,
                principal_id TEXT,
                route_id TEXT,
                route_policy_digest TEXT,
                credential_id TEXT,
                credential_version BIGINT,
                policy_hash TEXT,
                assignment_digest TEXT,
                oauth_provider TEXT,
                oauth_state_digest TEXT,
                oauth_pending_credential_id TEXT,
                canary_id TEXT,
                enrollment_session_id TEXT,
                enrollment_packet_digest TEXT,
                verifier_nonce_hash TEXT,
                enrollment_verifier_receipt_digest TEXT,
                enrollment_verifier_key_id TEXT,
                attestation_challenge_digest TEXT,
                attestation_challenge_issued_at TEXT,
                attestation_challenge_expires_at TEXT,
                attestation_challenge_value TEXT,
                runtime_evidence_digest TEXT,
                hardware_assurance_digest TEXT,
                hardware_verification_receipt_digest TEXT,
                hardware_verifier_key_id TEXT,
                release_identity_digest TEXT,
                current_host_identity_digest TEXT,
                proxy_server_statement_digest TEXT,
                trust_profile_digest TEXT,
                completion_identity_digest TEXT,
                final_authority_key_id TEXT,
                final_consumption_id TEXT,
                final_receipt_digest TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                terminal_at TEXT
            );

            CREATE INDEX IF NOT EXISTS setup_sessions_owner_updated
                ON setup_sessions (owner_id, updated_at);
            CREATE INDEX IF NOT EXISTS setup_sessions_assignee_updated
                ON setup_sessions (current_assignee_id, updated_at);
            CREATE INDEX IF NOT EXISTS setup_sessions_status_expiry
                ON setup_sessions (status, expires_at);
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_oauth_state
                ON setup_sessions (oauth_state_digest)
                WHERE oauth_state_digest IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_pending_oauth
                ON setup_sessions (oauth_pending_credential_id)
                WHERE oauth_pending_credential_id IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_canary
                ON setup_sessions (canary_id)
                WHERE canary_id IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_enrollment
                ON setup_sessions (enrollment_session_id)
                WHERE enrollment_session_id IS NOT NULL;
            CREATE TABLE IF NOT EXISTS setup_session_evidence (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES setup_sessions(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                verifier_key_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (session_id, kind),
                UNIQUE (evidence_digest)
            );

            CREATE INDEX IF NOT EXISTS setup_session_evidence_session_created
                ON setup_session_evidence (session_id, created_at);
            CREATE UNIQUE INDEX IF NOT EXISTS setup_session_evidence_one_kind
                ON setup_session_evidence (session_id, kind);
            CREATE UNIQUE INDEX IF NOT EXISTS setup_session_evidence_one_digest
                ON setup_session_evidence (evidence_digest);

            CREATE TABLE IF NOT EXISTS setup_session_events (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES setup_sessions(id) ON DELETE CASCADE,
                sequence BIGINT NOT NULL,
                transition TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                audit_status TEXT NOT NULL,
                audit_claim_id TEXT,
                audit_claimed_at TEXT,
                audit_attempts BIGINT NOT NULL DEFAULT 0,
                audited_at TEXT,
                audit_event_hash TEXT,
                audit_last_error TEXT,
                UNIQUE (session_id, sequence)
            );

            CREATE INDEX IF NOT EXISTS setup_session_events_session_sequence
                ON setup_session_events (session_id, sequence);
            CREATE INDEX IF NOT EXISTS setup_session_events_audit_outbox
                ON setup_session_events (audit_status, audit_claimed_at, created_at);

            CREATE TABLE IF NOT EXISTS metadata_audit_outbox (
                id TEXT PRIMARY KEY NOT NULL,
                event_type TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_id TEXT,
                event_json TEXT NOT NULL,
                event_digest TEXT NOT NULL,
                storage_format_version BIGINT,
                status TEXT NOT NULL,
                claim_id TEXT,
                claimed_at TEXT,
                attempts BIGINT NOT NULL DEFAULT 0,
                audited_at TEXT,
                audit_event_hash TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                UNIQUE (id, event_digest),
                CHECK (status IN ('pending', 'claimed', 'audited')),
                CHECK (
                    length(event_digest) = 71
                    AND substr(event_digest, 1, 7) = 'sha256:'
                    AND lower(event_digest) = event_digest
                )
            );

            CREATE INDEX IF NOT EXISTS metadata_audit_outbox_delivery
                ON metadata_audit_outbox (status, claimed_at, created_at, id);
            CREATE UNIQUE INDEX IF NOT EXISTS metadata_audit_outbox_id_event_digest
                ON metadata_audit_outbox (id, event_digest);

            CREATE TABLE IF NOT EXISTS rbac_authority_state (
                authority_id INTEGER PRIMARY KEY,
                generation BIGINT NOT NULL,
                state_digest TEXT NOT NULL,
                binding_table_revision BIGINT NOT NULL DEFAULT 0,
                verified_binding_table_revision BIGINT NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                CHECK (authority_id = 1),
                CHECK (generation >= 0),
                CHECK (binding_table_revision >= 0),
                CHECK (verified_binding_table_revision >= 0),
                CHECK (length(state_digest) = 71)
            );

            CREATE TABLE IF NOT EXISTS rbac_role_bindings (
                subject_id TEXT PRIMARY KEY,
                roles_json TEXT NOT NULL,
                status TEXT NOT NULL,
                generation BIGINT NOT NULL,
                binding_digest TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL,
                reason TEXT,
                deprovisioned_at TEXT,
                deprovisioned_by TEXT,
                CHECK (status IN ('active', 'deprovisioned')),
                CHECK (generation > 0),
                CHECK (length(binding_digest) = 71),
                CHECK (length(roles_json) <= 4096),
                CHECK (length(subject_id) <= 1024),
                CHECK (reason IS NULL OR length(reason) <= 500)
            );

            CREATE INDEX IF NOT EXISTS rbac_role_bindings_generation
                ON rbac_role_bindings (generation, subject_id);

            CREATE TABLE IF NOT EXISTS webauthn_trust_publications (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                previous_bundle_digest TEXT,
                bundle_digest TEXT NOT NULL UNIQUE,
                sequence BIGINT NOT NULL,
                rollback_epoch BIGINT NOT NULL,
                signing_key_id TEXT NOT NULL,
                bundle_json TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                withdrawn_credential_ids_json TEXT NOT NULL,
                audit_event_json TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts BIGINT NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at TEXT NOT NULL,
                published_at TEXT,
                CHECK (scope = 'global'),
                CHECK (status IN ('pending', 'published')),
                UNIQUE (rollback_epoch, sequence)
            );

            CREATE UNIQUE INDEX IF NOT EXISTS webauthn_trust_publications_one_pending
                ON webauthn_trust_publications (scope)
                WHERE status = 'pending';

            CREATE TABLE IF NOT EXISTS oidc_login_states (
                id TEXT PRIMARY KEY,
                encrypted_secret TEXT NOT NULL,
                encrypted_dek TEXT NOT NULL,
                secret_nonce TEXT NOT NULL,
                secret_ciphertext TEXT NOT NULL,
                secret_kek_id TEXT NOT NULL,
                credential_version INTEGER NOT NULL,
                browser_nonce_sha256 TEXT NOT NULL,
                oidc_nonce TEXT NOT NULL,
                source_key TEXT NOT NULL DEFAULT 'internal',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS oidc_login_states_expiry
                ON oidc_login_states (expires_at);

            CREATE TABLE IF NOT EXISTS oidc_login_rate_buckets (
                bucket_key TEXT PRIMARY KEY,
                attempt_count INTEGER NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS oidc_login_rate_buckets_expiry
                ON oidc_login_rate_buckets (expires_at);

            CREATE TABLE IF NOT EXISTS oauth_exchange_reservations (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL,
                requester_id TEXT NOT NULL,
                enrollment_original TEXT NOT NULL,
                credential_policy_json TEXT NOT NULL,
                consent_json TEXT NOT NULL,
                status TEXT NOT NULL,
                claim_request_digest TEXT,
                code_sha256 TEXT,
                contact_request_sha256 TEXT,
                raw_response_sha256 TEXT,
                raw_response_envelope_json TEXT,
                token_secret_sha256 TEXT,
                token_envelope_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (status IN ('prepared', 'claimed', 'retained', 'staged'))
            );

            CREATE TABLE IF NOT EXISTS credential_currentness_roots (
                id TEXT PRIMARY KEY,
                credential_id TEXT NOT NULL,
                credential_version BIGINT NOT NULL,
                epoch BIGINT NOT NULL,
                profile TEXT NOT NULL,
                status TEXT NOT NULL,
                origin_request_digest TEXT NOT NULL,
                predecessor_barrier_sha256 TEXT,
                barrier_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (credential_id, credential_version),
                CHECK (status IN ('open', 'quiescing', 'admitted', 'consumed'))
            );

            CREATE TABLE IF NOT EXISTS credential_currentness_holders (
                id TEXT PRIMARY KEY,
                root_id TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                credential_version BIGINT NOT NULL,
                epoch BIGINT NOT NULL,
                holder_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                control_plane_response_signing_key_id TEXT NOT NULL,
                control_plane_configuration_digest TEXT NOT NULL,
                registration_sha256 TEXT NOT NULL,
                registration_original_json TEXT NOT NULL,
                acknowledgement_sha256 TEXT,
                acknowledgement_original_json TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (root_id, holder_id),
                CHECK (status IN ('registered', 'acked'))
            );

            CREATE TABLE IF NOT EXISTS credential_currentness_challenges (
                id TEXT PRIMARY KEY,
                root_id TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                credential_version BIGINT NOT NULL,
                epoch BIGINT NOT NULL,
                holder_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                challenge TEXT NOT NULL,
                barrier_id TEXT,
                barrier_sha256 TEXT,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                status TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                consumed_request_digest TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (phase IN ('register', 'ack')),
                CHECK (status IN ('open', 'consumed'))
            );

            CREATE TABLE IF NOT EXISTS credential_currentness_barriers (
                id TEXT PRIMARY KEY,
                root_id TEXT NOT NULL UNIQUE,
                credential_id TEXT NOT NULL,
                credential_version BIGINT NOT NULL,
                epoch BIGINT NOT NULL,
                original_json TEXT NOT NULL,
                original_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                quiesce_request_digest TEXT NOT NULL,
                admit_request_digest TEXT,
                consume_request_digest TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (status IN ('quiescing', 'admitted', 'consumed'))
            );

            CREATE TABLE IF NOT EXISTS oauth_refresh_reservations (
                id TEXT PRIMARY KEY,
                credential_id TEXT NOT NULL,
                credential_version BIGINT NOT NULL,
                provider_id TEXT NOT NULL,
                enrollment_original TEXT NOT NULL,
                credential_original_json TEXT NOT NULL,
                generation_original_json TEXT NOT NULL,
                limits_json TEXT NOT NULL,
                claim_request_digest TEXT NOT NULL,
                owner_nonce_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                contact_request_sha256 TEXT NOT NULL,
                issued_work_id TEXT NOT NULL,
                superseded_work_id TEXT,
                issued_at_epoch_ns BIGINT NOT NULL,
                contact_expires_at_epoch_ns BIGINT NOT NULL,
                retention_expires_at_epoch_ns BIGINT NOT NULL,
                received_at_epoch_ns BIGINT,
                raw_response_sha256 TEXT,
                raw_response_envelope_json TEXT,
                issued_material_sha256 TEXT,
                issued_material_envelope_json TEXT,
                replacement_secret_sha256 TEXT,
                replacement_credential_sha256 TEXT,
                superseded_material_sha256 TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (credential_id, credential_version),
                CHECK (status IN ('claimed', 'retained', 'committed'))
            );

            CREATE TABLE IF NOT EXISTS oauth_setup_audit_links (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                outbox_id TEXT NOT NULL UNIQUE,
                outbox_event_digest TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS oauth_reconnect_authorizations (
                id TEXT PRIMARY KEY,
                authorization_original TEXT NOT NULL,
                authorization_sha256 TEXT NOT NULL UNIQUE,
                enrollment_original TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                credential_policy_json TEXT NOT NULL,
                original_affected_json TEXT NOT NULL,
                authorize_arguments_json TEXT NOT NULL,
                authorize_request_digest TEXT NOT NULL UNIQUE,
                currentness_barriers_json TEXT,
                fence_arguments_json TEXT,
                fence_request_digest TEXT UNIQUE,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                admission_expires_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (status IN ('authorized', 'fenced')),
                CHECK ((status = 'authorized') = (fence_request_digest IS NULL)),
                CHECK ((fence_request_digest IS NULL) = (fence_arguments_json IS NULL)
                    AND (fence_request_digest IS NULL) = (currentness_barriers_json IS NULL))
            );

            CREATE TABLE IF NOT EXISTS oauth_measured_reconnect_custody (
                id TEXT PRIMARY KEY,
                prepare_request_digest TEXT NOT NULL,
                preparation_arguments_json TEXT NOT NULL,
                claim_arguments_json TEXT,
                capture_arguments_json TEXT,
                stage_arguments_json TEXT,
                cancel_arguments_json TEXT,
                owner_nonce_sha256 TEXT,
                received_at_epoch_ns BIGINT,
                recovery_request_digest TEXT,
                recovery_expires_at_epoch_ns BIGINT,
                recovery_arguments_json TEXT,
                recovery_owner_nonce_sha256 TEXT,
                candidate_original_json TEXT,
                commit_request_digest TEXT UNIQUE,
                committed_credential_json TEXT,
                predecessor_original_json TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (status IN ('prepared', 'claimed', 'captured', 'staged', 'cancelled', 'committed')),
                CHECK ((claim_arguments_json IS NULL) = (owner_nonce_sha256 IS NULL)),
                CHECK ((capture_arguments_json IS NULL) = (received_at_epoch_ns IS NULL)),
                CHECK ((stage_arguments_json IS NULL) = (candidate_original_json IS NULL)),
                CHECK ((recovery_request_digest IS NULL) = (recovery_expires_at_epoch_ns IS NULL)
                    AND (recovery_request_digest IS NULL) = (recovery_arguments_json IS NULL)
                    AND (recovery_request_digest IS NULL) = (recovery_owner_nonce_sha256 IS NULL)),
                CHECK ((status = 'committed') = (commit_request_digest IS NOT NULL)),
                CHECK ((commit_request_digest IS NULL) = (committed_credential_json IS NULL)
                    AND (commit_request_digest IS NULL) = (predecessor_original_json IS NULL)),
                CHECK (cancel_arguments_json IS NULL OR claim_arguments_json IS NULL)
            );

            CREATE TABLE IF NOT EXISTS oauth_retirement_scope_heads (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL UNIQUE,
                scope_kind TEXT NOT NULL,
                provider_subject TEXT,
                sequence BIGINT NOT NULL CHECK (sequence > 0),
                scope_id TEXT NOT NULL UNIQUE,
                scope_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (provider_id IN ('google', 'x')),
                CHECK (scope_kind IN ('family', 'provider')),
                CHECK ((scope_kind = 'provider') = (provider_subject IS NULL))
            );

            CREATE TABLE IF NOT EXISTS oauth_retirement_scopes (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL,
                sequence BIGINT NOT NULL CHECK (sequence > 0),
                authorization_sha256 TEXT NOT NULL UNIQUE,
                previous_head_json TEXT,
                predecessors_json TEXT NOT NULL,
                affected_originals_json TEXT NOT NULL,
                inventory_original_json TEXT NOT NULL,
                currentness_barriers_json TEXT NOT NULL,
                fence_request_digest TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                UNIQUE (provider_id, sequence)
            );

            CREATE TABLE IF NOT EXISTS oauth_retirement_successions (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL,
                authorization_original TEXT NOT NULL,
                authorization_sha256 TEXT NOT NULL UNIQUE,
                enrollment_original TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                credential_policy_json TEXT NOT NULL,
                authorize_arguments_json TEXT NOT NULL,
                authorize_request_digest TEXT NOT NULL UNIQUE,
                approval_id TEXT NOT NULL UNIQUE,
                requester_credential_id TEXT NOT NULL,
                requester_evidence_expires_at TEXT NOT NULL,
                fence_arguments_json TEXT,
                fence_request_digest TEXT UNIQUE,
                scope_original_json TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                admission_expires_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (status IN ('requested', 'approved', 'fenced', 'committed')),
                CHECK ((status IN ('requested', 'approved')) = (fence_request_digest IS NULL)),
                CHECK ((fence_request_digest IS NULL) = (fence_arguments_json IS NULL)
                    AND (fence_request_digest IS NULL) = (scope_original_json IS NULL))
            );

            CREATE TABLE IF NOT EXISTS oauth_retirement_succession_snapshots (
                id TEXT PRIMARY KEY,
                authorization_id TEXT NOT NULL,
                authorization_sha256 TEXT NOT NULL,
                part TEXT NOT NULL,
                root_original_json TEXT NOT NULL,
                rows_original_json TEXT NOT NULL,
                acquisition_request_digest TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                UNIQUE (authorization_id, part)
            );

            CREATE TABLE IF NOT EXISTS oauth_retirement_succession_materials (
                id TEXT PRIMARY KEY,
                material_id TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                authorization_sha256 TEXT NOT NULL,
                material_original_json TEXT NOT NULL,
                claim_arguments_json TEXT NOT NULL,
                claim_request_digest TEXT NOT NULL UNIQUE,
                owner_nonce_sha256 TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status = 'claimed'),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (scope_id, material_id)
            );

            CREATE TABLE IF NOT EXISTS oauth_retirement_succession_attempts (
                id TEXT PRIMARY KEY,
                material_id TEXT NOT NULL,
                material_claim_id TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                token_purpose TEXT NOT NULL CHECK (token_purpose IN ('access', 'refresh')),
                contact_request_sha256 TEXT NOT NULL,
                contact_arguments_json TEXT NOT NULL,
                contact_request_digest TEXT NOT NULL UNIQUE,
                finish_arguments_json TEXT,
                finish_request_digest TEXT UNIQUE,
                transport_original TEXT,
                prior_contact_json TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (material_claim_id, token_purpose),
                CHECK (status IN ('contact-claimed', 'accepted', 'accepted-existing', 'rejected', 'unknown')),
                CHECK ((status IN ('contact-claimed', 'accepted-existing')) = (finish_request_digest IS NULL)),
                CHECK ((finish_request_digest IS NULL) = (finish_arguments_json IS NULL)
                    AND (finish_request_digest IS NULL) = (transport_original IS NULL)),
                CHECK ((status = 'accepted-existing') = (prior_contact_json IS NOT NULL))
            );

            CREATE TABLE IF NOT EXISTS oauth_retirement_successor_generations (
                id TEXT PRIMARY KEY,
                credential_id TEXT NOT NULL,
                credential_version BIGINT NOT NULL CHECK (credential_version > 0),
                scope_id TEXT NOT NULL,
                scope_sha256 TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                provider_subject TEXT NOT NULL,
                enrollment_sha256 TEXT NOT NULL,
                credential_sha256 TEXT NOT NULL,
                root_origin_request_digest TEXT NOT NULL UNIQUE,
                previous_association_sha256 TEXT,
                created_at TEXT NOT NULL,
                UNIQUE (credential_id, credential_version)
            );

            CREATE TABLE IF NOT EXISTS oauth_measured_succession_custody (
                id TEXT PRIMARY KEY,
                prepare_request_digest TEXT NOT NULL UNIQUE,
                preparation_arguments_json TEXT NOT NULL,
                claim_arguments_json TEXT,
                capture_arguments_json TEXT,
                stage_arguments_json TEXT,
                cancel_arguments_json TEXT,
                owner_nonce_sha256 TEXT,
                received_at_epoch_ns BIGINT,
                recovery_request_digest TEXT,
                recovery_expires_at_epoch_ns BIGINT,
                recovery_arguments_json TEXT,
                recovery_owner_nonce_sha256 TEXT,
                candidate_original_json TEXT,
                commit_request_digest TEXT UNIQUE,
                committed_credential_json TEXT,
                predecessor_original_json TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (status IN ('prepared', 'claimed', 'captured', 'staged', 'cancelled', 'committed')),
                CHECK ((claim_arguments_json IS NULL) = (owner_nonce_sha256 IS NULL)),
                CHECK ((capture_arguments_json IS NULL) = (received_at_epoch_ns IS NULL)),
                CHECK ((stage_arguments_json IS NULL) = (candidate_original_json IS NULL)),
                CHECK (recovery_request_digest IS NULL AND recovery_expires_at_epoch_ns IS NULL
                    AND recovery_arguments_json IS NULL AND recovery_owner_nonce_sha256 IS NULL),
                CHECK ((status = 'committed') = (commit_request_digest IS NOT NULL)),
                CHECK ((commit_request_digest IS NULL) = (committed_credential_json IS NULL)
                    AND (commit_request_digest IS NULL) = (predecessor_original_json IS NULL)),
                CHECK (cancel_arguments_json IS NULL OR claim_arguments_json IS NULL)
            );

            CREATE TABLE IF NOT EXISTS oauth_measured_setup_custody (
                id TEXT PRIMARY KEY,
                prepare_request_digest TEXT NOT NULL,
                preparation_arguments_json TEXT NOT NULL,
                claim_arguments_json TEXT,
                capture_arguments_json TEXT,
                stage_arguments_json TEXT,
                cancel_arguments_json TEXT,
                owner_nonce_sha256 TEXT,
                received_at_epoch_ns BIGINT,
                recovery_request_digest TEXT,
                recovery_expires_at_epoch_ns BIGINT,
                recovery_arguments_json TEXT,
                recovery_owner_nonce_sha256 TEXT,
                pending_original_json TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                setup_initial_json TEXT NOT NULL,
                setup_started_json TEXT NOT NULL,
                setup_final_json TEXT,
                CHECK (status IN ('prepared', 'claimed', 'captured', 'staged', 'cancelled')),
                CHECK ((claim_arguments_json IS NULL) = (owner_nonce_sha256 IS NULL)),
                CHECK ((capture_arguments_json IS NULL) = (received_at_epoch_ns IS NULL)),
                CHECK ((stage_arguments_json IS NULL) = (pending_original_json IS NULL)),
                CHECK ((recovery_request_digest IS NULL) = (recovery_expires_at_epoch_ns IS NULL)
                    AND (recovery_request_digest IS NULL) = (recovery_arguments_json IS NULL)
                    AND (recovery_request_digest IS NULL) = (recovery_owner_nonce_sha256 IS NULL)),
                CHECK ((status IN ('staged', 'cancelled')) = (setup_final_json IS NOT NULL)),
                CHECK (cancel_arguments_json IS NULL OR claim_arguments_json IS NULL)
            );

            CREATE TABLE IF NOT EXISTS oauth_measured_exchange_custody (
                id TEXT PRIMARY KEY,
                prepare_request_digest TEXT NOT NULL,
                preparation_arguments_json TEXT NOT NULL,
                claim_arguments_json TEXT,
                capture_arguments_json TEXT,
                stage_arguments_json TEXT,
                cancel_arguments_json TEXT,
                owner_nonce_sha256 TEXT,
                received_at_epoch_ns BIGINT,
                recovery_request_digest TEXT,
                recovery_expires_at_epoch_ns BIGINT,
                recovery_arguments_json TEXT,
                recovery_owner_nonce_sha256 TEXT,
                pending_original_json TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (status IN ('prepared', 'claimed', 'captured', 'staged', 'cancelled')),
                CHECK ((claim_arguments_json IS NULL) = (owner_nonce_sha256 IS NULL)),
                CHECK ((capture_arguments_json IS NULL) = (received_at_epoch_ns IS NULL)),
                CHECK ((stage_arguments_json IS NULL) = (pending_original_json IS NULL)),
                CHECK ((recovery_request_digest IS NULL) = (recovery_expires_at_epoch_ns IS NULL)
                    AND (recovery_request_digest IS NULL) = (recovery_arguments_json IS NULL)
                    AND (recovery_request_digest IS NULL) = (recovery_owner_nonce_sha256 IS NULL)),
                CHECK (cancel_arguments_json IS NULL OR claim_arguments_json IS NULL)
            );

            CREATE TABLE IF NOT EXISTS oauth_measured_refresh_cleanup_custody (
                id TEXT PRIMARY KEY,
                authorization_sha256 TEXT NOT NULL,
                claim_original_json TEXT NOT NULL,
                contact_originals_json TEXT NOT NULL,
                finish_originals_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS oauth_measured_refresh_custody (
                id TEXT PRIMARY KEY,
                credential_id TEXT NOT NULL,
                credential_version BIGINT NOT NULL,
                enrollment_original TEXT NOT NULL,
                assignment_original_json TEXT NOT NULL,
                claim_evidence_original_json TEXT NOT NULL,
                claim_request_json TEXT NOT NULL,
                capture_evidence_original_json TEXT,
                capture_request_json TEXT,
                commit_evidence_original_json TEXT,
                commit_request_json TEXT,
                recovery_request_digest TEXT,
                recovery_expires_at_epoch_ns BIGINT,
                recovery_evidence_original_json TEXT,
                recovery_owner_nonce_sha256 TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (credential_id, credential_version),
                CHECK (status IN ('claimed', 'captured', 'committed')),
                CHECK ((capture_request_json IS NULL) = (capture_evidence_original_json IS NULL)),
                CHECK ((commit_request_json IS NULL) = (commit_evidence_original_json IS NULL)),
                CHECK ((recovery_request_digest IS NULL) = (recovery_expires_at_epoch_ns IS NULL)
                    AND (recovery_request_digest IS NULL) = (recovery_evidence_original_json IS NULL)
                    AND (recovery_request_digest IS NULL) = (recovery_owner_nonce_sha256 IS NULL))
            );

            CREATE TABLE IF NOT EXISTS oauth_revocation_reservations (
                id TEXT PRIMARY KEY,
                authorization_original TEXT NOT NULL,
                authorization_sha256 TEXT NOT NULL,
                exchange_row_sha256 TEXT NOT NULL,
                original_work_json TEXT NOT NULL,
                owner_nonce_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (status IN ('claimed', 'unknown', 'observed-accepted', 'observed-rejected'))
            );

            CREATE TABLE IF NOT EXISTS oauth_revocation_attempts (
                id TEXT PRIMARY KEY,
                work_id TEXT NOT NULL,
                token_purpose TEXT NOT NULL,
                contact_request_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                transport_original TEXT,
                transport_sha256 TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (token_purpose IN ('access_token', 'refresh_token')),
                CHECK (status IN ('contact-claimed', 'accepted', 'rejected', 'unknown')),
                UNIQUE (work_id, token_purpose)
            );

            CREATE TABLE IF NOT EXISTS oauth_refresh_cleanup_reservations (
                id TEXT PRIMARY KEY,
                authorization_original TEXT NOT NULL,
                authorization_sha256 TEXT NOT NULL,
                refresh_row_sha256 TEXT NOT NULL,
                original_work_json TEXT NOT NULL,
                original_credential_json TEXT NOT NULL,
                original_generation_json TEXT NOT NULL,
                currentness_barrier_sha256 TEXT NOT NULL,
                claim_request_digest TEXT NOT NULL,
                owner_nonce_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (status IN ('claimed', 'unknown', 'observed-accepted', 'observed-rejected'))
            );

            CREATE TABLE IF NOT EXISTS oauth_refresh_cleanup_attempts (
                id TEXT PRIMARY KEY,
                work_id TEXT NOT NULL,
                token_purpose TEXT NOT NULL,
                contact_request_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                transport_original TEXT,
                transport_sha256 TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (token_purpose IN ('access_token', 'refresh_token')),
                CHECK (status IN ('contact-claimed', 'accepted', 'rejected', 'unknown')),
                UNIQUE (work_id, token_purpose)
            );

            CREATE TABLE IF NOT EXISTS oauth_family_retirements (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL,
                provider_subject TEXT NOT NULL,
                authorization_sha256 TEXT NOT NULL,
                work_id TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                credential_version BIGINT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (provider_id, provider_subject)
            );

            CREATE TABLE IF NOT EXISTS oauth_pending_family_retirements (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL,
                provider_subject TEXT NOT NULL,
                authorization_sha256 TEXT NOT NULL,
                pending_id TEXT NOT NULL,
                claim_request_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (provider_id, provider_subject)
            );

            CREATE TABLE IF NOT EXISTS oauth_pending_retirement_reservations (
                id TEXT PRIMARY KEY,
                authorization_original TEXT NOT NULL,
                authorization_sha256 TEXT NOT NULL,
                original_pending_json TEXT NOT NULL,
                original_affected_json TEXT NOT NULL,
                currentness_barriers_json TEXT NOT NULL,
                claim_request_digest TEXT NOT NULL,
                owner_nonce_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (status IN ('claimed', 'unknown', 'observed-accepted', 'observed-rejected'))
            );

            CREATE TABLE IF NOT EXISTS oauth_pending_retirement_attempts (
                id TEXT PRIMARY KEY,
                pending_id TEXT NOT NULL,
                token_purpose TEXT NOT NULL,
                contact_request_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                transport_original TEXT,
                transport_sha256 TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (token_purpose IN ('access_token', 'refresh_token')),
                CHECK (status IN ('contact-claimed', 'accepted', 'rejected', 'unknown')),
                UNIQUE (pending_id, token_purpose)
            );

            CREATE TABLE IF NOT EXISTS oauth_measured_pending_retirement_custody (
                id TEXT PRIMARY KEY,
                authorization_sha256 TEXT NOT NULL,
                claim_original_json TEXT NOT NULL,
                contact_originals_json TEXT NOT NULL,
                finish_originals_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS oauth_provider_retirements (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL UNIQUE,
                deployment_id TEXT NOT NULL,
                authorization_sha256 TEXT NOT NULL,
                source_profile TEXT NOT NULL,
                exchange_id TEXT NOT NULL,
                claim_request_digest TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS oauth_capture_retirement_reservations (
                id TEXT PRIMARY KEY,
                work_source TEXT NOT NULL,
                authorization_original TEXT NOT NULL,
                authorization_sha256 TEXT NOT NULL,
                original_work_json TEXT NOT NULL,
                original_affected_json TEXT NOT NULL,
                currentness_barriers_json TEXT NOT NULL,
                claim_request_digest TEXT NOT NULL,
                owner_nonce_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (status IN ('claimed', 'unknown', 'observed-accepted', 'observed-rejected'))
            );

            CREATE TABLE IF NOT EXISTS oauth_capture_retirement_attempts (
                id TEXT PRIMARY KEY,
                exchange_id TEXT NOT NULL,
                token_purpose TEXT NOT NULL,
                contact_request_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                transport_original TEXT,
                transport_sha256 TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (token_purpose IN ('access_token', 'refresh_token')),
                CHECK (status IN ('contact-claimed', 'accepted', 'rejected', 'unknown')),
                UNIQUE (exchange_id, token_purpose)
            );

            CREATE TABLE IF NOT EXISTS oauth_measured_capture_retirement_custody (
                id TEXT PRIMARY KEY,
                authorization_sha256 TEXT NOT NULL,
                claim_original_json TEXT NOT NULL,
                contact_originals_json TEXT NOT NULL,
                finish_originals_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS oauth_revocation_work (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                source TEXT NOT NULL,
                encrypted_secret TEXT NOT NULL,
                encrypted_dek TEXT NOT NULL,
                secret_nonce TEXT NOT NULL,
                secret_ciphertext TEXT NOT NULL,
                secret_kek_id TEXT NOT NULL,
                credential_version INTEGER NOT NULL,
                secret_updated_at TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                next_attempt_at TEXT NOT NULL,
                lease_owner TEXT,
                lease_until TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS oauth_revocation_work_due
                ON oauth_revocation_work (status, next_attempt_at);

            CREATE TABLE IF NOT EXISTS routes (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                match_host TEXT NOT NULL,
                match_path_prefix TEXT NOT NULL DEFAULT '/',
                credential_id TEXT REFERENCES credentials(id) ON DELETE SET NULL,
                injection TEXT NOT NULL DEFAULT '{}',
                policies TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approval_requests (
                id TEXT PRIMARY KEY,
                route_id TEXT REFERENCES routes(id) ON DELETE CASCADE,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                approved_until TEXT,
                decision_note TEXT,
                principal_id TEXT,
                credential_id TEXT,
                credential_version INTEGER,
                policy_hash TEXT,
                request_digest TEXT,
                operation_digest TEXT,
                canonical_request TEXT,
                redacted_display TEXT,
                grant_ttl_seconds INTEGER,
                grant_max_uses INTEGER,
                approver_policy_json TEXT,
                approver_policy_digest TEXT,
                approved_by TEXT,
                approval_authn TEXT,
                approver_webauthn_credential_id TEXT,
                verified_assertion_receipt_digest TEXT,
                approval_challenge_id TEXT,
                pending_key TEXT,
                CHECK (
                    (approver_policy_json IS NULL
                        AND approver_policy_digest IS NULL)
                    OR (
                        approver_policy_json IS NOT NULL
                        AND length(approver_policy_json)
                            BETWEEN 2 AND 65536
                        AND length(approver_policy_digest) = 71
                        AND substr(approver_policy_digest, 1, 7)
                            = 'sha256:'
                    )
                )
            );

            CREATE TABLE IF NOT EXISTS control_plane_approvals (
                id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                resource_id TEXT,
                payload_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                requester_id TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                request_json TEXT NOT NULL DEFAULT '{}',
                approved_by TEXT,
                approved_at TEXT,
                consumed_by TEXT,
                consumed_at TEXT,
                decision_note TEXT,
                approval_authn TEXT,
                approver_webauthn_credential_id TEXT
            );

            CREATE INDEX IF NOT EXISTS control_plane_approvals_pending_lookup
                ON control_plane_approvals (action, resource_id, payload_digest, status, expires_at);

            CREATE TABLE IF NOT EXISTS gmail_message_cache (
                route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
                message_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                source_url TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (route_id, message_id)
            );

            CREATE TABLE IF NOT EXISTS request_logs (
                id TEXT PRIMARY KEY,
                route_id TEXT,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                action TEXT NOT NULL,
                status_code INTEGER,
                reason TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approval_grants (
                id TEXT PRIMARY KEY,
                approval_request_id TEXT NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
                state TEXT NOT NULL,
                principal_id TEXT,
                route_id TEXT,
                credential_id TEXT,
                credential_version INTEGER,
                policy_hash TEXT,
                request_digest TEXT,
                operation_digest TEXT,
                approver_policy_json TEXT NOT NULL,
                approver_policy_digest TEXT NOT NULL,
                approver_webauthn_credential_id TEXT,
                verified_assertion_receipt_digest TEXT,
                uses_remaining INTEGER NOT NULL,
                valid_from TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                consumed_by_flow_id TEXT,
                reserved_attempt_id TEXT,
                reserved_at_epoch_ms BIGINT,
                reservation_expires_at_epoch_ms BIGINT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (length(approver_policy_json) BETWEEN 2 AND 65536),
                CHECK (
                    length(approver_policy_digest) = 71
                    AND substr(approver_policy_digest, 1, 7) = 'sha256:'
                )
            );

            CREATE TABLE IF NOT EXISTS approval_review_receipts (
                id TEXT PRIMARY KEY,
                approval_request_id TEXT NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
                reviewer_id TEXT NOT NULL,
                review_digest TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS approval_review_receipts_lookup
                ON approval_review_receipts (approval_request_id, reviewer_id, expires_at, used_at);

            CREATE TABLE IF NOT EXISTS approval_grant_consumptions (
                id TEXT PRIMARY KEY,
                grant_id TEXT NOT NULL REFERENCES approval_grants(id) ON DELETE CASCADE,
                approval_request_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL UNIQUE,
                flow_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                route_id TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                credential_version INTEGER NOT NULL,
                policy_hash TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                operation_digest TEXT,
                approver_policy_digest TEXT NOT NULL,
                verified_assertion_receipt_digest TEXT,
                authority_capability_id TEXT,
                authority_request_digest TEXT,
                outcome TEXT NOT NULL,
                uses_remaining_before INTEGER NOT NULL,
                uses_remaining_after INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                audited_at TEXT,
                audit_event_hash TEXT
                , CHECK (
                    length(approver_policy_digest) = 71
                    AND substr(approver_policy_digest, 1, 7) = 'sha256:'
                )
            );

            CREATE TABLE IF NOT EXISTS approval_events (
                id TEXT PRIMARY KEY,
                approval_request_id TEXT,
                event_type TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_id TEXT,
                event_json TEXT NOT NULL,
                prev_event_hash TEXT,
                event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_id TEXT,
                event_json TEXT NOT NULL,
                encrypted_canonical_event_json TEXT,
                storage_format_version BIGINT,
                prev_event_hash TEXT,
                event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rate_limit_counters (
                counter_key TEXT PRIMARY KEY,
                principal_id TEXT,
                route_id TEXT,
                credential_id TEXT,
                credential_version INTEGER,
                policy_hash TEXT,
                constraint_id TEXT,
                operation TEXT,
                encrypted_operation TEXT,
                operation_storage_version BIGINT,
                window_start_epoch_ms BIGINT NOT NULL,
                window_end_epoch_ms BIGINT NOT NULL,
                window_kind TEXT NOT NULL DEFAULT 'fixed',
                window_seconds INTEGER NOT NULL,
                max_count INTEGER NOT NULL,
                count INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS durable_budget_definitions (
                budget_key TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                route_id TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                credential_version BIGINT NOT NULL,
                policy_hash TEXT NOT NULL,
                constraint_id TEXT NOT NULL,
                unit_field TEXT NOT NULL,
                window_kind TEXT NOT NULL,
                window_seconds BIGINT NOT NULL,
                max_units BIGINT NOT NULL,
                last_observed_epoch_ms BIGINT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (window_kind = 'sliding'),
                CHECK (window_seconds > 0),
                CHECK (max_units > 0),
                CHECK (last_observed_epoch_ms >= 0)
            );

            CREATE TABLE IF NOT EXISTS durable_budget_events (
                reservation_id TEXT PRIMARY KEY,
                bundle_reservation_id TEXT,
                budget_key TEXT NOT NULL
                    REFERENCES durable_budget_definitions(budget_key) ON DELETE CASCADE,
                request_digest TEXT NOT NULL,
                operation_digest TEXT,
                units BIGINT NOT NULL,
                state TEXT NOT NULL,
                occurred_at_epoch_ms BIGINT NOT NULL,
                expires_at_epoch_ms BIGINT NOT NULL,
                reservation_expires_at_epoch_ms BIGINT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (units >= 0),
                CHECK (expires_at_epoch_ms > occurred_at_epoch_ms),
                CHECK (state IN (
                    'reserved', 'dispatched', 'committed', 'cancelled', 'expired'
                ))
            );

            CREATE INDEX IF NOT EXISTS durable_budget_events_active
                ON durable_budget_events (
                    budget_key, state, expires_at_epoch_ms, reservation_id
                );

            CREATE TABLE IF NOT EXISTS traversal_budget_chains (
                chain_key TEXT PRIMARY KEY,
                lineage_digest TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                route_id TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                credential_version BIGINT NOT NULL,
                policy_hash TEXT NOT NULL,
                constraint_id TEXT NOT NULL,
                state TEXT NOT NULL,
                started_at_epoch_ms BIGINT NOT NULL,
                expires_at_epoch_ms BIGINT NOT NULL,
                last_observed_epoch_ms BIGINT NOT NULL,
                max_pages BIGINT NOT NULL,
                max_records BIGINT NOT NULL,
                max_bytes BIGINT NOT NULL,
                page_count BIGINT NOT NULL DEFAULT 0,
                record_count BIGINT NOT NULL DEFAULT 0,
                byte_count BIGINT NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (state IN ('active', 'exhausted', 'expired', 'poisoned')),
                CHECK (expires_at_epoch_ms > started_at_epoch_ms),
                CHECK (last_observed_epoch_ms >= started_at_epoch_ms),
                CHECK (max_pages > 0),
                CHECK (max_records > 0),
                CHECK (max_bytes > 0),
                CHECK (page_count >= 0),
                CHECK (record_count >= 0),
                CHECK (byte_count >= 0)
            );

            CREATE TABLE IF NOT EXISTS traversal_budget_cursors (
                cursor_digest TEXT PRIMARY KEY,
                chain_key TEXT NOT NULL
                    REFERENCES traversal_budget_chains(chain_key) ON DELETE CASCADE,
                lineage_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                reserved_by TEXT,
                issued_at_epoch_ms BIGINT NOT NULL,
                expires_at_epoch_ms BIGINT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (state IN ('available', 'reserved', 'consumed')),
                CHECK (
                    (state = 'reserved' AND reserved_by IS NOT NULL)
                    OR (state != 'reserved' AND reserved_by IS NULL)
                )
            );

            CREATE INDEX IF NOT EXISTS traversal_budget_cursors_chain
                ON traversal_budget_cursors (
                    chain_key, state, expires_at_epoch_ms, cursor_digest
                );

            CREATE TABLE IF NOT EXISTS traversal_budget_page_reservations (
                reservation_id TEXT PRIMARY KEY,
                bundle_reservation_id TEXT,
                chain_key TEXT NOT NULL
                    REFERENCES traversal_budget_chains(chain_key) ON DELETE CASCADE,
                lineage_digest TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                request_cursor_digest TEXT,
                page_number BIGINT NOT NULL,
                state TEXT NOT NULL,
                response_digest TEXT,
                response_records BIGINT,
                response_bytes BIGINT,
                next_cursor_digest TEXT,
                reservation_expires_at_epoch_ms BIGINT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (page_number > 0),
                CHECK (state IN (
                    'reserved', 'dispatched', 'committed', 'cancelled',
                    'denied', 'indeterminate', 'expired'
                )),
                CHECK (response_records IS NULL OR response_records >= 0),
                CHECK (response_bytes IS NULL OR response_bytes >= 0)
            );

            CREATE INDEX IF NOT EXISTS traversal_budget_pages_chain
                ON traversal_budget_page_reservations (
                    chain_key, state, page_number, reservation_id
                );

            CREATE TABLE IF NOT EXISTS policy_state_bundles (
                reservation_id TEXT PRIMARY KEY,
                attempt_id TEXT NOT NULL UNIQUE,
                policy_hash TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                operation_digest TEXT NOT NULL,
                claim_digest TEXT NOT NULL,
                claims_json TEXT NOT NULL,
                release_binding_digest TEXT NOT NULL,
                reservation_deadline_at_epoch_ms BIGINT NOT NULL,
                state TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                dispatch_started_at_epoch_ms BIGINT,
                dispatch_deadline_at_epoch_ms BIGINT,
                completion_dispatch_deadline_at_epoch_ms BIGINT,
                response_evidence_digest TEXT,
                response_evidence_json TEXT,
                terminal_reason TEXT,
                response_body_sha256 TEXT,
                uncertainty TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (state IN (
                    'reserved', 'dispatched', 'committed', 'aborted',
                    'indeterminate', 'denied'
                ))
            );

            CREATE INDEX IF NOT EXISTS policy_state_bundles_state
                ON policy_state_bundles (state, updated_at, reservation_id);

            CREATE TABLE IF NOT EXISTS release_authorization_attempts (
                attempt_id TEXT PRIMARY KEY,
                binding_digest TEXT NOT NULL,
                binding_json TEXT NOT NULL,
                flow_id TEXT NOT NULL,
                state TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                route_id TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                credential_version BIGINT NOT NULL,
                policy_hash TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                operation_digest TEXT,
                operation_context_json TEXT NOT NULL,
                grant_id TEXT,
                approval_request_id TEXT,
                approver_policy_json TEXT,
                approver_policy_digest TEXT,
                reservation_expires_at_epoch_ms BIGINT NOT NULL,
                dispatch_started_at_epoch_ms BIGINT,
                dispatch_expires_at_epoch_ms BIGINT,
                completion_outcome TEXT,
                completed_at_epoch_ms BIGINT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (state IN (
                    'reserved', 'dispatching', 'committed', 'cancelled',
                    'committed_indeterminate'
                )),
                CHECK (
                    (grant_id IS NULL
                        AND approval_request_id IS NULL
                        AND approver_policy_json IS NULL
                        AND approver_policy_digest IS NULL)
                    OR (
                        grant_id IS NOT NULL
                        AND approval_request_id IS NOT NULL
                        AND length(approver_policy_json)
                            BETWEEN 2 AND 65536
                        AND length(approver_policy_digest) = 71
                        AND substr(approver_policy_digest, 1, 7)
                            = 'sha256:'
                    )
                )
            );

            CREATE INDEX IF NOT EXISTS release_authorization_attempts_reap
                ON release_authorization_attempts (
                    state, reservation_expires_at_epoch_ms,
                    dispatch_expires_at_epoch_ms, attempt_id
                );

            CREATE TABLE IF NOT EXISTS release_authorization_credential_issuances (
                attempt_id TEXT PRIMARY KEY
                    REFERENCES release_authorization_attempts(attempt_id) ON DELETE CASCADE,
                release_kind TEXT NOT NULL,
                reservation_id TEXT NOT NULL,
                binding_digest TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                operation_digest TEXT,
                quota_claims_digest TEXT NOT NULL,
                request_binding_sha256 TEXT NOT NULL,
                request_authority_sha256 TEXT NOT NULL,
                recipient_key_id TEXT NOT NULL,
                recipient_nonce_sha256 TEXT NOT NULL,
                reservation_expires_at_epoch_ms BIGINT NOT NULL,
                claimed_at_epoch_ms BIGINT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (recipient_key_id, recipient_nonce_sha256)
            );

            CREATE TABLE IF NOT EXISTS release_authorization_quota_reservations (
                attempt_id TEXT NOT NULL
                    REFERENCES release_authorization_attempts(attempt_id) ON DELETE CASCADE,
                counter_key TEXT NOT NULL,
                constraint_id TEXT NOT NULL,
                operation TEXT,
                encrypted_operation TEXT,
                operation_storage_version BIGINT,
                window_start_epoch_ms BIGINT NOT NULL,
                window_end_epoch_ms BIGINT NOT NULL,
                window_kind TEXT NOT NULL DEFAULT 'fixed',
                window_seconds INTEGER NOT NULL,
                max_count INTEGER NOT NULL,
                count_after INTEGER NOT NULL,
                reservation_state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (attempt_id, counter_key),
                CHECK (reservation_state IN (
                    'reserved', 'committed', 'refunded', 'refund_skipped_window'
                ))
            );

            CREATE INDEX IF NOT EXISTS release_authorization_quota_counter
                ON release_authorization_quota_reservations (counter_key, attempt_id);

            CREATE TABLE IF NOT EXISTS release_authorization_events (
                id TEXT PRIMARY KEY,
                attempt_id TEXT NOT NULL
                    REFERENCES release_authorization_attempts(attempt_id) ON DELETE CASCADE,
                event_type TEXT NOT NULL,
                actor_id TEXT,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                audited_at TEXT,
                audit_event_hash TEXT
            );

            CREATE INDEX IF NOT EXISTS release_authorization_events_pending_audit
                ON release_authorization_events (created_at, id)
                WHERE audited_at IS NULL;

            CREATE TABLE IF NOT EXISTS credential_lease_nonces (
                recipient_key_id TEXT NOT NULL,
                nonce_sha256 TEXT NOT NULL,
                expires_at_epoch_ms BIGINT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (recipient_key_id, nonce_sha256)
            );

            CREATE INDEX IF NOT EXISTS credential_lease_nonces_expiry
                ON credential_lease_nonces (expires_at_epoch_ms);

            CREATE TABLE IF NOT EXISTS credential_lease_replay_state (
                scope TEXT PRIMARY KEY,
                nonce_count BIGINT NOT NULL
            );

            INSERT INTO credential_lease_replay_state (scope, nonce_count)
            VALUES ('global', 0)
            ON CONFLICT (scope) DO NOTHING;

            CREATE TABLE IF NOT EXISTS credential_generations (
                credential_id TEXT PRIMARY KEY,
                last_version BIGINT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policy_high_water (
                scope TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                sequence BIGINT NOT NULL,
                rollback_epoch BIGINT NOT NULL,
                policy_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policy_publications (
                policy_hash TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                sequence BIGINT NOT NULL,
                rollback_epoch BIGINT NOT NULL,
                status TEXT NOT NULL,
                previous_policy_hash TEXT,
                created_at TEXT NOT NULL,
                committed_at TEXT,
                updated_at TEXT NOT NULL,
                CHECK (status IN ('pending', 'committed'))
            );

            CREATE INDEX IF NOT EXISTS policy_publications_scope_status
                ON policy_publications (scope, status, sequence);
            CREATE UNIQUE INDEX IF NOT EXISTS policy_publications_exact_identity
                ON policy_publications (
                    policy_hash, scope, policy_id, sequence, rollback_epoch,
                    previous_policy_hash, status
                );

            /*
             * Retired pre-v2 candidate tables. This block is intentionally inert:
             * it kept signed "current state" in mutable rows and is not authority.
             * Fresh and empty legacy tables are removed before this script runs.
             *
            CREATE TABLE IF NOT EXISTS policy_candidate_artifacts (
                artifact_digest TEXT PRIMARY KEY,
                candidate_id TEXT NOT NULL UNIQUE,
                scope TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                policy_sequence BIGINT NOT NULL,
                rollback_epoch BIGINT NOT NULL,
                policy_hash TEXT NOT NULL UNIQUE,
                policy_bundle_digest TEXT NOT NULL UNIQUE,
                predecessor_policy_sequence BIGINT NOT NULL,
                predecessor_rollback_epoch BIGINT NOT NULL,
                predecessor_policy_hash TEXT NOT NULL,
                active_policy_hash_at_stage TEXT NOT NULL,
                compiler_digest TEXT NOT NULL,
                schema_digest TEXT NOT NULL,
                evaluator_abi_digest TEXT NOT NULL,
                policy_bundle_json TEXT NOT NULL,
                artifact_statement_json TEXT NOT NULL,
                artifact_size_bytes BIGINT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                created_by TEXT NOT NULL,
                created_at_epoch_ns BIGINT NOT NULL,
                created_outbox_id TEXT NOT NULL UNIQUE
                    REFERENCES metadata_audit_outbox(id) ON DELETE RESTRICT,
                UNIQUE (
                    policy_id, rollback_epoch, policy_sequence
                ),
                UNIQUE (
                    artifact_digest, policy_id, policy_sequence,
                    rollback_epoch, policy_hash, predecessor_policy_sequence,
                    predecessor_rollback_epoch, predecessor_policy_hash
                ),
                CHECK (scope = 'active'),
                CHECK (policy_sequence > 0),
                CHECK (rollback_epoch > 0),
                CHECK (predecessor_policy_sequence > 0),
                CHECK (predecessor_rollback_epoch > 0),
                CHECK (policy_sequence > predecessor_policy_sequence),
                CHECK (rollback_epoch >= predecessor_rollback_epoch),
                CHECK (artifact_size_bytes > 0),
                CHECK (created_at_epoch_ns >= 0),
                CHECK (predecessor_policy_hash = active_policy_hash_at_stage),
                CHECK (policy_hash <> predecessor_policy_hash),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (length(candidate_id) BETWEEN 1 AND 256),
                CHECK (length(policy_id) BETWEEN 1 AND 256),
                CHECK (length(signing_key_id) BETWEEN 1 AND 1024),
                CHECK (length(signature) BETWEEN 1 AND 4096),
                CHECK (length(policy_bundle_json) BETWEEN 2 AND 8388608),
                CHECK (length(artifact_statement_json) BETWEEN 2 AND 1048576),
                CHECK (
                    length(artifact_digest) = 71
                    AND substr(artifact_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(policy_hash) = 71
                    AND substr(policy_hash, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(policy_bundle_digest) = 71
                    AND substr(policy_bundle_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(predecessor_policy_hash) = 71
                    AND substr(predecessor_policy_hash, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(active_policy_hash_at_stage) = 71
                    AND substr(active_policy_hash_at_stage, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(compiler_digest) = 71
                    AND substr(compiler_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(schema_digest) = 71
                    AND substr(schema_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(evaluator_abi_digest) = 71
                    AND substr(evaluator_abi_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(signature_digest) = 71
                    AND substr(signature_digest, 1, 7) = 'sha256:'
                )
            );

            CREATE INDEX IF NOT EXISTS policy_candidate_artifacts_predecessor
                ON policy_candidate_artifacts (
                    scope, predecessor_policy_hash, policy_sequence
                );

            CREATE TABLE IF NOT EXISTS policy_canaries (
                canary_id TEXT PRIMARY KEY,
                candidate_artifact_digest TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                candidate_policy_sequence BIGINT NOT NULL,
                candidate_rollback_epoch BIGINT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                predecessor_policy_sequence BIGINT NOT NULL,
                predecessor_rollback_epoch BIGINT NOT NULL,
                predecessor_policy_hash TEXT NOT NULL,
                active_policy_hash_at_start TEXT NOT NULL,
                canary_generation BIGINT NOT NULL,
                status TEXT NOT NULL,
                revision BIGINT NOT NULL,
                thresholds_digest TEXT NOT NULL,
                assignment_digest TEXT,
                sealed_checkpoint_root_digest TEXT,
                sealed_instance_set_digest TEXT,
                readiness_statement_json TEXT,
                readiness_statement_digest TEXT,
                readiness_revision BIGINT,
                activation_attempt_id TEXT,
                activation_request_digest TEXT,
                activation_publication_digest TEXT,
                committed_policy_hash TEXT,
                active_high_water_digest TEXT,
                expected_instance_count BIGINT NOT NULL,
                minimum_evaluation_count BIGINT NOT NULL,
                state_statement_json TEXT NOT NULL,
                state_digest TEXT NOT NULL UNIQUE,
                previous_state_digest TEXT,
                state_signing_key_id TEXT NOT NULL,
                state_signature TEXT NOT NULL,
                state_signature_digest TEXT NOT NULL UNIQUE,
                created_by TEXT NOT NULL,
                created_at_epoch_ns BIGINT NOT NULL,
                updated_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                observation_started_at_epoch_ns BIGINT,
                sealed_at_epoch_ns BIGINT,
                terminal_at_epoch_ns BIGINT,
                last_transition_outbox_id TEXT NOT NULL UNIQUE
                    REFERENCES metadata_audit_outbox(id) ON DELETE RESTRICT,
                UNIQUE (
                    canary_id, candidate_artifact_digest, candidate_policy_hash
                ),
                UNIQUE (
                    canary_id, candidate_artifact_digest,
                    candidate_policy_hash, predecessor_policy_hash
                ),
                UNIQUE (
                    canary_id, candidate_artifact_digest,
                    candidate_policy_hash, predecessor_policy_hash,
                    assignment_digest
                ),
                UNIQUE (
                    canary_id, candidate_artifact_digest, policy_id,
                    candidate_policy_sequence, candidate_rollback_epoch,
                    candidate_policy_hash, predecessor_policy_sequence,
                    predecessor_rollback_epoch, predecessor_policy_hash
                ),
                UNIQUE (
                    canary_id, candidate_artifact_digest,
                    candidate_policy_hash, predecessor_policy_hash,
                    readiness_revision, readiness_statement_digest,
                    sealed_checkpoint_root_digest, thresholds_digest,
                    sealed_instance_set_digest
                ),
                UNIQUE (candidate_artifact_digest, canary_generation),
                FOREIGN KEY (
                    candidate_artifact_digest, policy_id,
                    candidate_policy_sequence, candidate_rollback_epoch,
                    candidate_policy_hash, predecessor_policy_sequence,
                    predecessor_rollback_epoch, predecessor_policy_hash
                ) REFERENCES policy_candidate_artifacts (
                    artifact_digest, policy_id, policy_sequence,
                    rollback_epoch, policy_hash, predecessor_policy_sequence,
                    predecessor_rollback_epoch, predecessor_policy_hash
                ) ON DELETE RESTRICT,
                CHECK (
                    status IN (
                        'staged', 'distributing', 'observing', 'sealing',
                        'ready', 'activating', 'active', 'verifying',
                        'completed', 'failed', 'cancelled', 'expired',
                        'superseded'
                    )
                ),
                CHECK (canary_generation > 0),
                CHECK (candidate_policy_sequence > predecessor_policy_sequence),
                CHECK (
                    candidate_rollback_epoch >= predecessor_rollback_epoch
                ),
                CHECK (revision > 0),
                CHECK (expected_instance_count > 0),
                CHECK (minimum_evaluation_count > 0),
                CHECK (created_at_epoch_ns >= 0),
                CHECK (updated_at_epoch_ns >= created_at_epoch_ns),
                CHECK (expires_at_epoch_ns > created_at_epoch_ns),
                CHECK (
                    observation_started_at_epoch_ns IS NULL
                    OR observation_started_at_epoch_ns >= created_at_epoch_ns
                ),
                CHECK (
                    sealed_at_epoch_ns IS NULL
                    OR (
                        observation_started_at_epoch_ns IS NOT NULL
                        AND sealed_at_epoch_ns >= observation_started_at_epoch_ns
                    )
                ),
                CHECK (
                    terminal_at_epoch_ns IS NULL
                    OR terminal_at_epoch_ns >= created_at_epoch_ns
                ),
                CHECK (predecessor_policy_hash = active_policy_hash_at_start),
                CHECK (candidate_policy_hash <> predecessor_policy_hash),
                CHECK (
                    readiness_revision IS NULL OR readiness_revision > 0
                ),
                CHECK (
                    (revision = 1 AND previous_state_digest IS NULL)
                    OR (revision > 1 AND previous_state_digest IS NOT NULL)
                ),
                CHECK (
                    (
                        status = 'staged'
                        AND assignment_digest IS NULL
                        AND sealed_checkpoint_root_digest IS NULL
                        AND sealed_instance_set_digest IS NULL
                        AND readiness_statement_json IS NULL
                        AND readiness_statement_digest IS NULL
                        AND readiness_revision IS NULL
                        AND observation_started_at_epoch_ns IS NULL
                        AND sealed_at_epoch_ns IS NULL
                    )
                    OR (
                        status = 'distributing'
                        AND assignment_digest IS NOT NULL
                        AND sealed_checkpoint_root_digest IS NULL
                        AND sealed_instance_set_digest IS NULL
                        AND readiness_statement_json IS NULL
                        AND readiness_statement_digest IS NULL
                        AND readiness_revision IS NULL
                        AND observation_started_at_epoch_ns IS NULL
                        AND sealed_at_epoch_ns IS NULL
                    )
                    OR (
                        status IN ('observing', 'sealing')
                        AND assignment_digest IS NOT NULL
                        AND sealed_checkpoint_root_digest IS NULL
                        AND sealed_instance_set_digest IS NULL
                        AND readiness_statement_json IS NULL
                        AND readiness_statement_digest IS NULL
                        AND readiness_revision IS NULL
                        AND observation_started_at_epoch_ns IS NOT NULL
                        AND sealed_at_epoch_ns IS NULL
                    )
                    OR (
                        status IN (
                            'ready', 'activating', 'active', 'verifying',
                            'completed'
                        )
                        AND assignment_digest IS NOT NULL
                        AND sealed_checkpoint_root_digest IS NOT NULL
                        AND sealed_instance_set_digest IS NOT NULL
                        AND readiness_statement_json IS NOT NULL
                        AND readiness_statement_digest IS NOT NULL
                        AND readiness_revision IS NOT NULL
                        AND observation_started_at_epoch_ns IS NOT NULL
                        AND sealed_at_epoch_ns IS NOT NULL
                    )
                    OR status IN (
                        'failed', 'cancelled', 'expired', 'superseded'
                    )
                ),
                CHECK (
                    (
                        activation_attempt_id IS NULL
                        AND activation_request_digest IS NULL
                    )
                    OR (
                        activation_attempt_id IS NOT NULL
                        AND activation_request_digest IS NOT NULL
                    )
                ),
                CHECK (
                    (
                        activation_publication_digest IS NULL
                        AND committed_policy_hash IS NULL
                        AND active_high_water_digest IS NULL
                    )
                    OR (
                        activation_publication_digest IS NOT NULL
                        AND committed_policy_hash = candidate_policy_hash
                        AND active_high_water_digest IS NOT NULL
                    )
                ),
                CHECK (
                    (
                        status IN (
                            'staged', 'distributing', 'observing', 'sealing',
                            'ready'
                        )
                        AND activation_attempt_id IS NULL
                        AND activation_request_digest IS NULL
                        AND activation_publication_digest IS NULL
                        AND committed_policy_hash IS NULL
                        AND active_high_water_digest IS NULL
                    )
                    OR (
                        status = 'activating'
                        AND activation_attempt_id IS NOT NULL
                        AND activation_request_digest IS NOT NULL
                        AND activation_publication_digest IS NULL
                        AND committed_policy_hash IS NULL
                        AND active_high_water_digest IS NULL
                    )
                    OR (
                        status IN ('active', 'verifying', 'completed')
                        AND activation_attempt_id IS NOT NULL
                        AND activation_request_digest IS NOT NULL
                        AND activation_publication_digest IS NOT NULL
                        AND committed_policy_hash = candidate_policy_hash
                        AND active_high_water_digest IS NOT NULL
                    )
                    OR status IN (
                        'failed', 'cancelled', 'expired', 'superseded'
                    )
                ),
                CHECK (
                    (
                        status IN (
                            'completed', 'failed', 'cancelled', 'expired',
                            'superseded'
                        )
                        AND terminal_at_epoch_ns IS NOT NULL
                    )
                    OR (
                        status NOT IN (
                            'completed', 'failed', 'cancelled', 'expired',
                            'superseded'
                        )
                        AND terminal_at_epoch_ns IS NULL
                    )
                ),
                CHECK (
                    length(candidate_artifact_digest) = 71
                    AND substr(candidate_artifact_digest, 1, 7) = 'sha256:'
                ),
                CHECK (length(policy_id) BETWEEN 1 AND 256),
                CHECK (
                    length(candidate_policy_hash) = 71
                    AND substr(candidate_policy_hash, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(predecessor_policy_hash) = 71
                    AND substr(predecessor_policy_hash, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(active_policy_hash_at_start) = 71
                    AND substr(active_policy_hash_at_start, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(thresholds_digest) = 71
                    AND substr(thresholds_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    assignment_digest IS NULL
                    OR (
                        length(assignment_digest) = 71
                        AND substr(assignment_digest, 1, 7) = 'sha256:'
                    )
                ),
                CHECK (
                    sealed_checkpoint_root_digest IS NULL
                    OR (
                        length(sealed_checkpoint_root_digest) = 71
                        AND substr(
                            sealed_checkpoint_root_digest, 1, 7
                        ) = 'sha256:'
                    )
                ),
                CHECK (
                    sealed_instance_set_digest IS NULL
                    OR (
                        length(sealed_instance_set_digest) = 71
                        AND substr(
                            sealed_instance_set_digest, 1, 7
                        ) = 'sha256:'
                    )
                ),
                CHECK (
                    readiness_statement_digest IS NULL
                    OR (
                        length(readiness_statement_digest) = 71
                        AND substr(
                            readiness_statement_digest, 1, 7
                        ) = 'sha256:'
                    )
                ),
                CHECK (
                    activation_request_digest IS NULL
                    OR (
                        length(activation_request_digest) = 71
                        AND substr(
                            activation_request_digest, 1, 7
                        ) = 'sha256:'
                    )
                ),
                CHECK (
                    activation_publication_digest IS NULL
                    OR (
                        length(activation_publication_digest) = 71
                        AND substr(
                            activation_publication_digest, 1, 7
                        ) = 'sha256:'
                    )
                ),
                CHECK (
                    committed_policy_hash IS NULL
                    OR (
                        length(committed_policy_hash) = 71
                        AND substr(committed_policy_hash, 1, 7) = 'sha256:'
                    )
                ),
                CHECK (
                    active_high_water_digest IS NULL
                    OR (
                        length(active_high_water_digest) = 71
                        AND substr(
                            active_high_water_digest, 1, 7
                        ) = 'sha256:'
                    )
                ),
                CHECK (
                    length(state_digest) = 71
                    AND substr(state_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    previous_state_digest IS NULL
                    OR (
                        length(previous_state_digest) = 71
                        AND substr(previous_state_digest, 1, 7) = 'sha256:'
                    )
                ),
                CHECK (
                    length(state_signature_digest) = 71
                    AND substr(state_signature_digest, 1, 7) = 'sha256:'
                ),
                CHECK (length(state_statement_json) BETWEEN 2 AND 1048576),
                CHECK (
                    readiness_statement_json IS NULL
                    OR length(readiness_statement_json) BETWEEN 2 AND 1048576
                ),
                CHECK (length(state_signing_key_id) BETWEEN 1 AND 1024),
                CHECK (length(state_signature) BETWEEN 1 AND 4096)
            );

            CREATE UNIQUE INDEX IF NOT EXISTS policy_canaries_one_live_artifact
                ON policy_canaries (candidate_artifact_digest)
                WHERE status IN (
                    'staged', 'distributing', 'observing', 'sealing',
                    'ready', 'activating', 'active', 'verifying'
                );

            CREATE INDEX IF NOT EXISTS policy_canaries_status_updated
                ON policy_canaries (
                    status, updated_at_epoch_ns, candidate_artifact_digest
                );

            CREATE TABLE IF NOT EXISTS policy_canary_instances (
                canary_id TEXT NOT NULL,
                candidate_artifact_digest TEXT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                predecessor_policy_hash TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                status TEXT NOT NULL,
                revision BIGINT NOT NULL,
                assignment_digest TEXT NOT NULL,
                decision_gate_binary_digest TEXT NOT NULL,
                compiler_digest TEXT NOT NULL,
                evaluator_abi_digest TEXT NOT NULL,
                workload_identity_digest TEXT NOT NULL,
                tee_attestation_digest TEXT NOT NULL,
                boot_signing_key_id TEXT NOT NULL,
                boot_public_key_digest TEXT NOT NULL,
                last_checkpoint_sequence BIGINT NOT NULL DEFAULT 0,
                last_checkpoint_digest TEXT,
                last_request_sequence_end BIGINT,
                last_window_ended_at_epoch_ns BIGINT,
                load_receipt_json TEXT,
                load_receipt_digest TEXT UNIQUE,
                load_receipt_signature TEXT,
                load_receipt_signature_digest TEXT UNIQUE,
                state_statement_json TEXT NOT NULL,
                state_digest TEXT NOT NULL UNIQUE,
                previous_state_digest TEXT,
                state_signature TEXT NOT NULL,
                state_signature_digest TEXT NOT NULL UNIQUE,
                assigned_at_epoch_ns BIGINT NOT NULL,
                loaded_at_epoch_ns BIGINT,
                last_seen_at_epoch_ns BIGINT NOT NULL,
                sealed_at_epoch_ns BIGINT,
                expires_at_epoch_ns BIGINT NOT NULL,
                terminal_at_epoch_ns BIGINT,
                last_transition_outbox_id TEXT NOT NULL UNIQUE
                    REFERENCES metadata_audit_outbox(id) ON DELETE RESTRICT,
                PRIMARY KEY (canary_id, instance_id, boot_id),
                UNIQUE (
                    canary_id, candidate_artifact_digest,
                    candidate_policy_hash, predecessor_policy_hash,
                    assignment_digest, instance_id, boot_id,
                    boot_signing_key_id, boot_public_key_digest
                ),
                FOREIGN KEY (
                    canary_id, candidate_artifact_digest,
                    candidate_policy_hash, predecessor_policy_hash,
                    assignment_digest
                ) REFERENCES policy_canaries (
                    canary_id, candidate_artifact_digest,
                    candidate_policy_hash, predecessor_policy_hash,
                    assignment_digest
                ) ON DELETE RESTRICT,
                CHECK (
                    status IN (
                        'assigned', 'loaded', 'observing', 'sealed',
                        'failed', 'evicted', 'expired'
                    )
                ),
                CHECK (revision > 0),
                CHECK (last_checkpoint_sequence >= 0),
                CHECK (
                    (
                        last_checkpoint_sequence = 0
                        AND last_checkpoint_digest IS NULL
                        AND last_request_sequence_end IS NULL
                        AND last_window_ended_at_epoch_ns IS NULL
                    )
                    OR (
                        last_checkpoint_sequence > 0
                        AND last_checkpoint_digest IS NOT NULL
                        AND last_request_sequence_end IS NOT NULL
                        AND last_request_sequence_end >= 0
                        AND last_window_ended_at_epoch_ns IS NOT NULL
                        AND last_window_ended_at_epoch_ns >= 0
                    )
                ),
                CHECK (assigned_at_epoch_ns >= 0),
                CHECK (last_seen_at_epoch_ns >= assigned_at_epoch_ns),
                CHECK (expires_at_epoch_ns > assigned_at_epoch_ns),
                CHECK (
                    loaded_at_epoch_ns IS NULL
                    OR loaded_at_epoch_ns >= assigned_at_epoch_ns
                ),
                CHECK (
                    sealed_at_epoch_ns IS NULL
                    OR (
                        loaded_at_epoch_ns IS NOT NULL
                        AND sealed_at_epoch_ns >= loaded_at_epoch_ns
                    )
                ),
                CHECK (
                    terminal_at_epoch_ns IS NULL
                    OR terminal_at_epoch_ns >= assigned_at_epoch_ns
                ),
                CHECK (
                    (revision = 1 AND previous_state_digest IS NULL)
                    OR (revision > 1 AND previous_state_digest IS NOT NULL)
                ),
                CHECK (
                    (
                        status = 'assigned'
                        AND load_receipt_json IS NULL
                        AND load_receipt_digest IS NULL
                        AND load_receipt_signature IS NULL
                        AND load_receipt_signature_digest IS NULL
                        AND loaded_at_epoch_ns IS NULL
                        AND sealed_at_epoch_ns IS NULL
                        AND terminal_at_epoch_ns IS NULL
                    )
                    OR (
                        status IN ('loaded', 'observing')
                        AND load_receipt_json IS NOT NULL
                        AND load_receipt_digest IS NOT NULL
                        AND load_receipt_signature IS NOT NULL
                        AND load_receipt_signature_digest IS NOT NULL
                        AND loaded_at_epoch_ns IS NOT NULL
                        AND sealed_at_epoch_ns IS NULL
                        AND terminal_at_epoch_ns IS NULL
                    )
                    OR (
                        status = 'sealed'
                        AND load_receipt_json IS NOT NULL
                        AND load_receipt_digest IS NOT NULL
                        AND load_receipt_signature IS NOT NULL
                        AND load_receipt_signature_digest IS NOT NULL
                        AND loaded_at_epoch_ns IS NOT NULL
                        AND sealed_at_epoch_ns IS NOT NULL
                        AND last_checkpoint_sequence > 0
                        AND terminal_at_epoch_ns IS NOT NULL
                    )
                    OR (
                        status IN ('failed', 'evicted', 'expired')
                        AND terminal_at_epoch_ns IS NOT NULL
                    )
                ),
                CHECK (length(instance_id) BETWEEN 1 AND 1024),
                CHECK (length(boot_id) BETWEEN 1 AND 1024),
                CHECK (length(boot_signing_key_id) BETWEEN 1 AND 1024),
                CHECK (
                    length(candidate_artifact_digest) = 71
                    AND substr(candidate_artifact_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(candidate_policy_hash) = 71
                    AND substr(candidate_policy_hash, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(predecessor_policy_hash) = 71
                    AND substr(predecessor_policy_hash, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(assignment_digest) = 71
                    AND substr(assignment_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(decision_gate_binary_digest) = 71
                    AND substr(
                        decision_gate_binary_digest, 1, 7
                    ) = 'sha256:'
                ),
                CHECK (
                    length(compiler_digest) = 71
                    AND substr(compiler_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(evaluator_abi_digest) = 71
                    AND substr(evaluator_abi_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(workload_identity_digest) = 71
                    AND substr(
                        workload_identity_digest, 1, 7
                    ) = 'sha256:'
                ),
                CHECK (
                    length(tee_attestation_digest) = 71
                    AND substr(tee_attestation_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(boot_public_key_digest) = 71
                    AND substr(boot_public_key_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    last_checkpoint_digest IS NULL
                    OR (
                        length(last_checkpoint_digest) = 71
                        AND substr(last_checkpoint_digest, 1, 7) = 'sha256:'
                    )
                ),
                CHECK (
                    load_receipt_digest IS NULL
                    OR (
                        length(load_receipt_digest) = 71
                        AND substr(load_receipt_digest, 1, 7) = 'sha256:'
                    )
                ),
                CHECK (
                    load_receipt_signature_digest IS NULL
                    OR (
                        length(load_receipt_signature_digest) = 71
                        AND substr(
                            load_receipt_signature_digest, 1, 7
                        ) = 'sha256:'
                    )
                ),
                CHECK (
                    length(state_digest) = 71
                    AND substr(state_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    previous_state_digest IS NULL
                    OR (
                        length(previous_state_digest) = 71
                        AND substr(previous_state_digest, 1, 7) = 'sha256:'
                    )
                ),
                CHECK (
                    length(state_signature_digest) = 71
                    AND substr(state_signature_digest, 1, 7) = 'sha256:'
                ),
                CHECK (length(state_statement_json) BETWEEN 2 AND 1048576),
                CHECK (
                    load_receipt_json IS NULL
                    OR length(load_receipt_json) BETWEEN 2 AND 1048576
                ),
                CHECK (
                    load_receipt_signature IS NULL
                    OR length(load_receipt_signature) BETWEEN 1 AND 4096
                ),
                CHECK (length(state_signature) BETWEEN 1 AND 4096)
            );

            CREATE INDEX IF NOT EXISTS policy_canary_instances_status
                ON policy_canary_instances (
                    canary_id, status, last_seen_at_epoch_ns, instance_id
                );

            CREATE TABLE IF NOT EXISTS policy_canary_checkpoints (
                canary_id TEXT NOT NULL,
                candidate_artifact_digest TEXT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                sequence BIGINT NOT NULL,
                previous_sequence BIGINT,
                previous_checkpoint_digest TEXT,
                checkpoint_digest TEXT NOT NULL UNIQUE,
                assignment_digest TEXT NOT NULL,
                active_policy_hash TEXT NOT NULL,
                boot_signing_key_id TEXT NOT NULL,
                boot_public_key_digest TEXT NOT NULL,
                request_sequence_start BIGINT NOT NULL,
                request_sequence_end BIGINT NOT NULL,
                previous_request_sequence_end BIGINT,
                window_started_at_epoch_ns BIGINT NOT NULL,
                window_ended_at_epoch_ns BIGINT NOT NULL,
                previous_window_ended_at_epoch_ns BIGINT,
                observed_request_count BIGINT NOT NULL,
                evaluated_request_count BIGINT NOT NULL,
                active_permit_count BIGINT NOT NULL,
                active_deny_count BIGINT NOT NULL,
                active_conditional_count BIGINT NOT NULL,
                active_indeterminate_count BIGINT NOT NULL,
                candidate_permit_count BIGINT NOT NULL,
                candidate_deny_count BIGINT NOT NULL,
                candidate_conditional_count BIGINT NOT NULL,
                candidate_indeterminate_count BIGINT NOT NULL,
                comparable_count BIGINT NOT NULL,
                not_comparable_count BIGINT NOT NULL,
                dropped_request_count BIGINT NOT NULL,
                evaluation_error_count BIGINT NOT NULL,
                queue_overflow_count BIGINT NOT NULL,
                deadline_exceeded_count BIGINT NOT NULL,
                response_validation_failure_count BIGINT NOT NULL,
                active_permit_candidate_permit_count BIGINT NOT NULL,
                active_permit_candidate_deny_count BIGINT NOT NULL,
                active_permit_candidate_conditional_count BIGINT NOT NULL,
                active_permit_candidate_indeterminate_count BIGINT NOT NULL,
                active_permit_candidate_dropped_count BIGINT NOT NULL,
                active_permit_candidate_error_count BIGINT NOT NULL,
                active_deny_candidate_permit_count BIGINT NOT NULL,
                active_deny_candidate_deny_count BIGINT NOT NULL,
                active_deny_candidate_conditional_count BIGINT NOT NULL,
                active_deny_candidate_indeterminate_count BIGINT NOT NULL,
                active_deny_candidate_dropped_count BIGINT NOT NULL,
                active_deny_candidate_error_count BIGINT NOT NULL,
                active_conditional_candidate_permit_count BIGINT NOT NULL,
                active_conditional_candidate_deny_count BIGINT NOT NULL,
                active_conditional_candidate_conditional_count BIGINT NOT NULL,
                active_conditional_candidate_indeterminate_count BIGINT NOT NULL,
                active_conditional_candidate_dropped_count BIGINT NOT NULL,
                active_conditional_candidate_error_count BIGINT NOT NULL,
                active_indeterminate_candidate_permit_count BIGINT NOT NULL,
                active_indeterminate_candidate_deny_count BIGINT NOT NULL,
                active_indeterminate_candidate_conditional_count BIGINT NOT NULL,
                active_indeterminate_candidate_indeterminate_count BIGINT NOT NULL,
                active_indeterminate_candidate_dropped_count BIGINT NOT NULL,
                active_indeterminate_candidate_error_count BIGINT NOT NULL,
                checkpoint_json TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                created_at_epoch_ns BIGINT NOT NULL,
                created_outbox_id TEXT NOT NULL UNIQUE
                    REFERENCES metadata_audit_outbox(id) ON DELETE RESTRICT,
                PRIMARY KEY (canary_id, instance_id, boot_id, sequence),
                UNIQUE (
                    canary_id, instance_id, boot_id, sequence,
                    checkpoint_digest, request_sequence_end,
                    window_ended_at_epoch_ns
                ),
                FOREIGN KEY (canary_id, instance_id, boot_id)
                    REFERENCES policy_canary_instances (
                        canary_id, instance_id, boot_id
                    ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, candidate_artifact_digest,
                    candidate_policy_hash, active_policy_hash,
                    assignment_digest, instance_id, boot_id,
                    boot_signing_key_id, boot_public_key_digest
                ) REFERENCES policy_canary_instances (
                    canary_id, candidate_artifact_digest,
                    candidate_policy_hash, predecessor_policy_hash,
                    assignment_digest, instance_id, boot_id,
                    boot_signing_key_id, boot_public_key_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, instance_id, boot_id, previous_sequence,
                    previous_checkpoint_digest, previous_request_sequence_end,
                    previous_window_ended_at_epoch_ns
                ) REFERENCES policy_canary_checkpoints (
                    canary_id, instance_id, boot_id, sequence,
                    checkpoint_digest, request_sequence_end,
                    window_ended_at_epoch_ns
                ) ON DELETE RESTRICT,
                CHECK (sequence > 0),
                CHECK (
                    (
                        sequence = 1
                        AND previous_sequence IS NULL
                        AND previous_checkpoint_digest IS NULL
                        AND previous_request_sequence_end IS NULL
                        AND previous_window_ended_at_epoch_ns IS NULL
                    )
                    OR (
                        sequence > 1
                        AND previous_sequence = sequence - 1
                        AND previous_checkpoint_digest IS NOT NULL
                        AND previous_request_sequence_end IS NOT NULL
                        AND request_sequence_start
                            = previous_request_sequence_end + 1
                        AND previous_window_ended_at_epoch_ns IS NOT NULL
                        AND window_started_at_epoch_ns
                            = previous_window_ended_at_epoch_ns
                    )
                ),
                CHECK (request_sequence_start >= 0),
                CHECK (request_sequence_end >= request_sequence_start),
                CHECK (window_started_at_epoch_ns >= 0),
                CHECK (window_ended_at_epoch_ns >= window_started_at_epoch_ns),
                CHECK (created_at_epoch_ns >= window_ended_at_epoch_ns),
                CHECK (observed_request_count >= 0),
                CHECK (evaluated_request_count >= 0),
                CHECK (active_permit_count >= 0),
                CHECK (active_deny_count >= 0),
                CHECK (active_conditional_count >= 0),
                CHECK (active_indeterminate_count >= 0),
                CHECK (candidate_permit_count >= 0),
                CHECK (candidate_deny_count >= 0),
                CHECK (candidate_conditional_count >= 0),
                CHECK (candidate_indeterminate_count >= 0),
                CHECK (comparable_count >= 0),
                CHECK (not_comparable_count >= 0),
                CHECK (dropped_request_count >= 0),
                CHECK (evaluation_error_count >= 0),
                CHECK (queue_overflow_count >= 0),
                CHECK (deadline_exceeded_count >= 0),
                CHECK (response_validation_failure_count >= 0),
                CHECK (active_permit_candidate_permit_count >= 0),
                CHECK (active_permit_candidate_deny_count >= 0),
                CHECK (active_permit_candidate_conditional_count >= 0),
                CHECK (active_permit_candidate_indeterminate_count >= 0),
                CHECK (active_permit_candidate_dropped_count >= 0),
                CHECK (active_permit_candidate_error_count >= 0),
                CHECK (active_deny_candidate_permit_count >= 0),
                CHECK (active_deny_candidate_deny_count >= 0),
                CHECK (active_deny_candidate_conditional_count >= 0),
                CHECK (active_deny_candidate_indeterminate_count >= 0),
                CHECK (active_deny_candidate_dropped_count >= 0),
                CHECK (active_deny_candidate_error_count >= 0),
                CHECK (active_conditional_candidate_permit_count >= 0),
                CHECK (active_conditional_candidate_deny_count >= 0),
                CHECK (active_conditional_candidate_conditional_count >= 0),
                CHECK (active_conditional_candidate_indeterminate_count >= 0),
                CHECK (active_conditional_candidate_dropped_count >= 0),
                CHECK (active_conditional_candidate_error_count >= 0),
                CHECK (active_indeterminate_candidate_permit_count >= 0),
                CHECK (active_indeterminate_candidate_deny_count >= 0),
                CHECK (
                    active_indeterminate_candidate_conditional_count >= 0
                ),
                CHECK (
                    active_indeterminate_candidate_indeterminate_count >= 0
                ),
                CHECK (active_indeterminate_candidate_dropped_count >= 0),
                CHECK (active_indeterminate_candidate_error_count >= 0),
                CHECK (
                    observed_request_count
                    = active_permit_count
                    + active_deny_count
                    + active_conditional_count
                    + active_indeterminate_count
                ),
                CHECK (
                    observed_request_count
                    = evaluated_request_count
                    + dropped_request_count
                    + evaluation_error_count
                ),
                CHECK (
                    evaluated_request_count
                    = candidate_permit_count
                    + candidate_deny_count
                    + candidate_conditional_count
                    + candidate_indeterminate_count
                ),
                CHECK (
                    evaluated_request_count
                    = comparable_count + not_comparable_count
                ),
                CHECK (
                    active_permit_count
                    = active_permit_candidate_permit_count
                    + active_permit_candidate_deny_count
                    + active_permit_candidate_conditional_count
                    + active_permit_candidate_indeterminate_count
                    + active_permit_candidate_dropped_count
                    + active_permit_candidate_error_count
                ),
                CHECK (
                    active_deny_count
                    = active_deny_candidate_permit_count
                    + active_deny_candidate_deny_count
                    + active_deny_candidate_conditional_count
                    + active_deny_candidate_indeterminate_count
                    + active_deny_candidate_dropped_count
                    + active_deny_candidate_error_count
                ),
                CHECK (
                    active_conditional_count
                    = active_conditional_candidate_permit_count
                    + active_conditional_candidate_deny_count
                    + active_conditional_candidate_conditional_count
                    + active_conditional_candidate_indeterminate_count
                    + active_conditional_candidate_dropped_count
                    + active_conditional_candidate_error_count
                ),
                CHECK (
                    active_indeterminate_count
                    = active_indeterminate_candidate_permit_count
                    + active_indeterminate_candidate_deny_count
                    + active_indeterminate_candidate_conditional_count
                    + active_indeterminate_candidate_indeterminate_count
                    + active_indeterminate_candidate_dropped_count
                    + active_indeterminate_candidate_error_count
                ),
                CHECK (
                    candidate_permit_count
                    = active_permit_candidate_permit_count
                    + active_deny_candidate_permit_count
                    + active_conditional_candidate_permit_count
                    + active_indeterminate_candidate_permit_count
                ),
                CHECK (
                    candidate_deny_count
                    = active_permit_candidate_deny_count
                    + active_deny_candidate_deny_count
                    + active_conditional_candidate_deny_count
                    + active_indeterminate_candidate_deny_count
                ),
                CHECK (
                    candidate_conditional_count
                    = active_permit_candidate_conditional_count
                    + active_deny_candidate_conditional_count
                    + active_conditional_candidate_conditional_count
                    + active_indeterminate_candidate_conditional_count
                ),
                CHECK (
                    candidate_indeterminate_count
                    = active_permit_candidate_indeterminate_count
                    + active_deny_candidate_indeterminate_count
                    + active_conditional_candidate_indeterminate_count
                    + active_indeterminate_candidate_indeterminate_count
                ),
                CHECK (
                    dropped_request_count
                    = active_permit_candidate_dropped_count
                    + active_deny_candidate_dropped_count
                    + active_conditional_candidate_dropped_count
                    + active_indeterminate_candidate_dropped_count
                ),
                CHECK (
                    evaluation_error_count
                    = active_permit_candidate_error_count
                    + active_deny_candidate_error_count
                    + active_conditional_candidate_error_count
                    + active_indeterminate_candidate_error_count
                ),
                CHECK (queue_overflow_count <= dropped_request_count),
                CHECK (
                    deadline_exceeded_count
                    <= dropped_request_count + evaluation_error_count
                ),
                CHECK (
                    response_validation_failure_count
                    <= evaluated_request_count
                ),
                CHECK (
                    length(candidate_artifact_digest) = 71
                    AND substr(candidate_artifact_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(candidate_policy_hash) = 71
                    AND substr(candidate_policy_hash, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(checkpoint_digest) = 71
                    AND substr(checkpoint_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    previous_checkpoint_digest IS NULL
                    OR (
                        length(previous_checkpoint_digest) = 71
                        AND substr(
                            previous_checkpoint_digest, 1, 7
                        ) = 'sha256:'
                    )
                ),
                CHECK (
                    length(assignment_digest) = 71
                    AND substr(assignment_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(active_policy_hash) = 71
                    AND substr(active_policy_hash, 1, 7) = 'sha256:'
                ),
                CHECK (signing_key_id = boot_signing_key_id),
                CHECK (length(boot_signing_key_id) BETWEEN 1 AND 1024),
                CHECK (
                    length(boot_public_key_digest) = 71
                    AND substr(boot_public_key_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(signature_digest) = 71
                    AND substr(signature_digest, 1, 7) = 'sha256:'
                ),
                CHECK (length(checkpoint_json) BETWEEN 2 AND 1048576),
                CHECK (length(signing_key_id) BETWEEN 1 AND 1024),
                CHECK (length(signature) BETWEEN 1 AND 4096)
            );

            CREATE INDEX IF NOT EXISTS policy_canary_checkpoints_chain
                ON policy_canary_checkpoints (
                    canary_id, instance_id, boot_id, sequence
                );

            CREATE INDEX IF NOT EXISTS policy_canary_checkpoints_window
                ON policy_canary_checkpoints (
                    canary_id, window_ended_at_epoch_ns, sequence
                );

            CREATE TABLE IF NOT EXISTS policy_activation_attempts (
                activation_attempt_id TEXT PRIMARY KEY,
                canary_id TEXT NOT NULL,
                candidate_artifact_digest TEXT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                candidate_policy_sequence BIGINT NOT NULL,
                candidate_rollback_epoch BIGINT NOT NULL,
                predecessor_policy_hash TEXT NOT NULL,
                expected_active_policy_hash TEXT NOT NULL,
                expected_active_policy_sequence BIGINT NOT NULL,
                expected_active_rollback_epoch BIGINT NOT NULL,
                canary_revision BIGINT NOT NULL,
                readiness_revision BIGINT NOT NULL,
                readiness_statement_digest TEXT NOT NULL,
                sealed_checkpoint_root_digest TEXT NOT NULL,
                thresholds_digest TEXT NOT NULL,
                sealed_instance_set_digest TEXT NOT NULL,
                activation_request_json TEXT NOT NULL,
                activation_request_digest TEXT NOT NULL UNIQUE,
                approval_request_digest TEXT NOT NULL,
                approval_consumption_id TEXT UNIQUE,
                approval_evidence_digest TEXT UNIQUE,
                publication_digest TEXT UNIQUE,
                committed_policy_hash TEXT,
                uncertainty_digest TEXT UNIQUE,
                status TEXT NOT NULL,
                revision BIGINT NOT NULL,
                state_statement_json TEXT NOT NULL,
                state_digest TEXT NOT NULL UNIQUE,
                previous_state_digest TEXT,
                state_signing_key_id TEXT NOT NULL,
                state_signature TEXT NOT NULL,
                state_signature_digest TEXT NOT NULL UNIQUE,
                requested_by TEXT NOT NULL,
                created_at_epoch_ns BIGINT NOT NULL,
                updated_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                approved_at_epoch_ns BIGINT,
                published_at_epoch_ns BIGINT,
                terminal_at_epoch_ns BIGINT,
                last_transition_outbox_id TEXT NOT NULL UNIQUE
                    REFERENCES metadata_audit_outbox(id) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, candidate_artifact_digest, policy_id,
                    candidate_policy_sequence, candidate_rollback_epoch,
                    candidate_policy_hash, expected_active_policy_sequence,
                    expected_active_rollback_epoch, predecessor_policy_hash
                ) REFERENCES policy_canaries (
                    canary_id, candidate_artifact_digest, policy_id,
                    candidate_policy_sequence, candidate_rollback_epoch,
                    candidate_policy_hash, predecessor_policy_sequence,
                    predecessor_rollback_epoch, predecessor_policy_hash
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, candidate_artifact_digest,
                    candidate_policy_hash, predecessor_policy_hash,
                    readiness_revision, readiness_statement_digest,
                    sealed_checkpoint_root_digest, thresholds_digest,
                    sealed_instance_set_digest
                ) REFERENCES policy_canaries (
                    canary_id, candidate_artifact_digest,
                    candidate_policy_hash, predecessor_policy_hash,
                    readiness_revision, readiness_statement_digest,
                    sealed_checkpoint_root_digest, thresholds_digest,
                    sealed_instance_set_digest
                ) ON DELETE RESTRICT,
                CHECK (
                    status IN (
                        'prepared', 'awaiting_approval', 'approved',
                        'publishing', 'committed', 'verifying', 'completed',
                        'denied', 'failed', 'expired', 'cancelled',
                        'superseded', 'indeterminate'
                    )
                ),
                CHECK (candidate_policy_sequence > 0),
                CHECK (candidate_rollback_epoch > 0),
                CHECK (expected_active_policy_sequence > 0),
                CHECK (expected_active_rollback_epoch >= 0),
                CHECK (
                    candidate_policy_sequence > expected_active_policy_sequence
                ),
                CHECK (
                    candidate_rollback_epoch >= expected_active_rollback_epoch
                ),
                CHECK (canary_revision > 0),
                CHECK (readiness_revision > 0),
                CHECK (revision > 0),
                CHECK (predecessor_policy_hash = expected_active_policy_hash),
                CHECK (candidate_policy_hash <> predecessor_policy_hash),
                CHECK (created_at_epoch_ns >= 0),
                CHECK (updated_at_epoch_ns >= created_at_epoch_ns),
                CHECK (expires_at_epoch_ns > created_at_epoch_ns),
                CHECK (
                    approved_at_epoch_ns IS NULL
                    OR approved_at_epoch_ns >= created_at_epoch_ns
                ),
                CHECK (
                    published_at_epoch_ns IS NULL
                    OR (
                        approved_at_epoch_ns IS NOT NULL
                        AND published_at_epoch_ns >= approved_at_epoch_ns
                    )
                ),
                CHECK (
                    terminal_at_epoch_ns IS NULL
                    OR terminal_at_epoch_ns >= created_at_epoch_ns
                ),
                CHECK (
                    (revision = 1 AND previous_state_digest IS NULL)
                    OR (revision > 1 AND previous_state_digest IS NOT NULL)
                ),
                CHECK (
                    (
                        approval_consumption_id IS NULL
                        AND approval_evidence_digest IS NULL
                        AND approved_at_epoch_ns IS NULL
                    )
                    OR (
                        approval_consumption_id IS NOT NULL
                        AND approval_evidence_digest IS NOT NULL
                        AND approved_at_epoch_ns IS NOT NULL
                    )
                ),
                CHECK (
                    (
                        publication_digest IS NULL
                        AND committed_policy_hash IS NULL
                        AND published_at_epoch_ns IS NULL
                    )
                    OR (
                        publication_digest IS NOT NULL
                        AND committed_policy_hash = candidate_policy_hash
                        AND published_at_epoch_ns IS NOT NULL
                    )
                ),
                CHECK (
                    (
                        status IN ('prepared', 'awaiting_approval')
                        AND approval_consumption_id IS NULL
                        AND approval_evidence_digest IS NULL
                        AND approved_at_epoch_ns IS NULL
                        AND publication_digest IS NULL
                        AND committed_policy_hash IS NULL
                        AND published_at_epoch_ns IS NULL
                        AND uncertainty_digest IS NULL
                    )
                    OR (
                        status IN ('approved', 'publishing')
                        AND approval_consumption_id IS NOT NULL
                        AND approval_evidence_digest IS NOT NULL
                        AND approved_at_epoch_ns IS NOT NULL
                        AND publication_digest IS NULL
                        AND committed_policy_hash IS NULL
                        AND published_at_epoch_ns IS NULL
                        AND uncertainty_digest IS NULL
                    )
                    OR (
                        status IN ('committed', 'verifying', 'completed')
                        AND approval_consumption_id IS NOT NULL
                        AND approval_evidence_digest IS NOT NULL
                        AND approved_at_epoch_ns IS NOT NULL
                        AND publication_digest IS NOT NULL
                        AND committed_policy_hash = candidate_policy_hash
                        AND published_at_epoch_ns IS NOT NULL
                        AND uncertainty_digest IS NULL
                    )
                    OR (
                        status IN (
                            'denied', 'failed', 'expired', 'cancelled',
                            'superseded'
                        )
                        AND publication_digest IS NULL
                        AND committed_policy_hash IS NULL
                        AND published_at_epoch_ns IS NULL
                        AND uncertainty_digest IS NULL
                    )
                    OR (
                        status = 'indeterminate'
                        AND approval_consumption_id IS NOT NULL
                        AND approval_evidence_digest IS NOT NULL
                        AND approved_at_epoch_ns IS NOT NULL
                        AND publication_digest IS NULL
                        AND committed_policy_hash IS NULL
                        AND published_at_epoch_ns IS NULL
                        AND uncertainty_digest IS NOT NULL
                    )
                ),
                CHECK (
                    (
                        status IN (
                            'completed', 'denied', 'failed', 'expired',
                            'cancelled', 'superseded', 'indeterminate'
                        )
                        AND terminal_at_epoch_ns IS NOT NULL
                    )
                    OR (
                        status NOT IN (
                            'completed', 'denied', 'failed', 'expired',
                            'cancelled', 'superseded', 'indeterminate'
                        )
                        AND terminal_at_epoch_ns IS NULL
                    )
                ),
                CHECK (length(policy_id) BETWEEN 1 AND 256),
                CHECK (
                    length(candidate_artifact_digest) = 71
                    AND substr(candidate_artifact_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(candidate_policy_hash) = 71
                    AND substr(candidate_policy_hash, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(predecessor_policy_hash) = 71
                    AND substr(predecessor_policy_hash, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(expected_active_policy_hash) = 71
                    AND substr(
                        expected_active_policy_hash, 1, 7
                    ) = 'sha256:'
                ),
                CHECK (
                    length(readiness_statement_digest) = 71
                    AND substr(
                        readiness_statement_digest, 1, 7
                    ) = 'sha256:'
                ),
                CHECK (
                    length(sealed_checkpoint_root_digest) = 71
                    AND substr(
                        sealed_checkpoint_root_digest, 1, 7
                    ) = 'sha256:'
                ),
                CHECK (
                    length(thresholds_digest) = 71
                    AND substr(thresholds_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(sealed_instance_set_digest) = 71
                    AND substr(
                        sealed_instance_set_digest, 1, 7
                    ) = 'sha256:'
                ),
                CHECK (
                    length(activation_request_digest) = 71
                    AND substr(activation_request_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(approval_request_digest) = 71
                    AND substr(approval_request_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    approval_evidence_digest IS NULL
                    OR (
                        length(approval_evidence_digest) = 71
                        AND substr(
                            approval_evidence_digest, 1, 7
                        ) = 'sha256:'
                    )
                ),
                CHECK (
                    publication_digest IS NULL
                    OR (
                        length(publication_digest) = 71
                        AND substr(publication_digest, 1, 7) = 'sha256:'
                    )
                ),
                CHECK (
                    committed_policy_hash IS NULL
                    OR (
                        length(committed_policy_hash) = 71
                        AND substr(committed_policy_hash, 1, 7) = 'sha256:'
                    )
                ),
                CHECK (
                    uncertainty_digest IS NULL
                    OR (
                        length(uncertainty_digest) = 71
                        AND substr(uncertainty_digest, 1, 7) = 'sha256:'
                    )
                ),
                CHECK (
                    length(state_digest) = 71
                    AND substr(state_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    previous_state_digest IS NULL
                    OR (
                        length(previous_state_digest) = 71
                        AND substr(previous_state_digest, 1, 7) = 'sha256:'
                    )
                ),
                CHECK (
                    length(state_signature_digest) = 71
                    AND substr(state_signature_digest, 1, 7) = 'sha256:'
                ),
                CHECK (length(activation_request_json) BETWEEN 2 AND 1048576),
                CHECK (length(state_statement_json) BETWEEN 2 AND 1048576),
                CHECK (length(state_signing_key_id) BETWEEN 1 AND 1024),
                CHECK (length(state_signature) BETWEEN 1 AND 4096)
            );

            CREATE UNIQUE INDEX IF NOT EXISTS policy_activation_one_live_canary
                ON policy_activation_attempts (canary_id)
                WHERE status IN (
                    'prepared', 'awaiting_approval', 'approved', 'publishing',
                    'committed', 'verifying'
                );

            CREATE INDEX IF NOT EXISTS policy_activation_attempts_status
                ON policy_activation_attempts (
                    status, updated_at_epoch_ns, activation_attempt_id
                );
            */

            CREATE TABLE IF NOT EXISTS policy_authority_v8_legacy_archive (
                contract_id TEXT NOT NULL,
                source_version BIGINT NOT NULL,
                source_schema_fingerprint TEXT NOT NULL,
                source_row_set_digest TEXT NOT NULL,
                table_name TEXT NOT NULL,
                row_ordinal BIGINT NOT NULL,
                primary_key_json TEXT NOT NULL,
                row_json TEXT NOT NULL,
                row_digest TEXT NOT NULL UNIQUE,
                archived_at TEXT NOT NULL,
                PRIMARY KEY (contract_id, table_name, row_ordinal),
                CHECK (
                    contract_id =
                    'serverware.policyCandidateAuthorityOfflineMigration/v1:v0-v3-v4-v5-v6-v7-to-v8'
                ),
                CHECK (source_version IN (0, 3, 4, 5, 6, 7)),
                CHECK (row_ordinal > 0),
                CHECK (length(table_name) BETWEEN 1 AND 128),
                CHECK (length(primary_key_json) BETWEEN 2 AND 1048576),
                CHECK (length(row_json) BETWEEN 2 AND 8388608),
                CHECK (
                    length(source_schema_fingerprint) = 71
                    AND substr(source_schema_fingerprint, 1, 7) = 'sha256:'
                    AND lower(source_schema_fingerprint) =
                        source_schema_fingerprint
                ),
                CHECK (
                    length(source_row_set_digest) = 71
                    AND substr(source_row_set_digest, 1, 7) = 'sha256:'
                    AND lower(source_row_set_digest) = source_row_set_digest
                ),
                CHECK (
                    length(row_digest) = 71
                    AND substr(row_digest, 1, 7) = 'sha256:'
                    AND lower(row_digest) = row_digest
                )
            );

            CREATE TABLE IF NOT EXISTS
                policy_authority_v8_offline_migration_receipts (
                    contract_id TEXT PRIMARY KEY,
                    source_version BIGINT NOT NULL,
                    target_version BIGINT NOT NULL,
                    source_schema_fingerprint TEXT NOT NULL,
                    source_row_set_digest TEXT NOT NULL,
                    source_row_count BIGINT NOT NULL,
                    archive_root_digest TEXT NOT NULL,
                    archive_row_count BIGINT NOT NULL,
                    outbox_root_digest TEXT NOT NULL,
                    outbox_row_count BIGINT NOT NULL,
                    legacy_outbox_table TEXT,
                    receipt_json TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    prepared_at TEXT NOT NULL,
                    CHECK (
                        contract_id =
                        'serverware.policyCandidateAuthorityOfflineMigration/v1:v0-v3-v4-v5-v6-v7-to-v8'
                    ),
                    CHECK (source_version IN (0, 3, 4, 5, 6, 7)),
                    CHECK (target_version = 8),
                    CHECK (source_row_count >= 0),
                    CHECK (archive_row_count >= 0),
                    CHECK (outbox_row_count >= 0),
                    CHECK (
                        legacy_outbox_table IS NULL
                        OR legacy_outbox_table =
                            'metadata_audit_outbox_legacy_v6'
                    ),
                    CHECK (status = 'prepared'),
                    CHECK (length(receipt_json) BETWEEN 2 AND 1048576),
                    CHECK (
                        length(source_schema_fingerprint) = 71
                        AND substr(
                            source_schema_fingerprint, 1, 7
                        ) = 'sha256:'
                        AND lower(source_schema_fingerprint) =
                            source_schema_fingerprint
                    ),
                    CHECK (
                        length(source_row_set_digest) = 71
                        AND substr(source_row_set_digest, 1, 7) = 'sha256:'
                        AND lower(source_row_set_digest) =
                            source_row_set_digest
                    ),
                    CHECK (
                        length(archive_root_digest) = 71
                        AND substr(archive_root_digest, 1, 7) = 'sha256:'
                        AND lower(archive_root_digest) = archive_root_digest
                    ),
                    CHECK (
                        length(outbox_root_digest) = 71
                        AND substr(outbox_root_digest, 1, 7) = 'sha256:'
                        AND lower(outbox_root_digest) = outbox_root_digest
                    ),
                    CHECK (
                        length(receipt_digest) = 71
                        AND substr(receipt_digest, 1, 7) = 'sha256:'
                        AND lower(receipt_digest) = receipt_digest
                    )
                );

            CREATE TABLE IF NOT EXISTS policy_authority_schema_contracts (
                schema_version BIGINT PRIMARY KEY,
                contract_id TEXT NOT NULL UNIQUE,
                source_revision TEXT NOT NULL,
                source_contract_digest TEXT NOT NULL UNIQUE,
                structural_manifest_json TEXT NOT NULL,
                structural_manifest_digest TEXT NOT NULL UNIQUE,
                offline_migration_receipt_digest TEXT UNIQUE,
                installed_at TEXT NOT NULL,
                CHECK (schema_version = 9),
                CHECK (
                    contract_id =
                        'serverware.policyCandidateAuthoritySchema/v9'
                ),
                CHECK (
                    source_revision =
                        'serverware.policyCandidateAuthoritySource/2026-07-30.351'
                ),
                CHECK (
                    length(structural_manifest_json)
                    BETWEEN 2 AND 8388608
                ),
                CHECK (
                    length(source_contract_digest) = 71
                    AND substr(source_contract_digest, 1, 7) = 'sha256:'
                    AND lower(source_contract_digest) =
                        source_contract_digest
                ),
                CHECK (
                    length(structural_manifest_digest) = 71
                    AND substr(structural_manifest_digest, 1, 7) = 'sha256:'
                    AND lower(structural_manifest_digest) =
                        structural_manifest_digest
                ),
                CHECK (
                    offline_migration_receipt_digest IS NULL
                    OR (
                        length(offline_migration_receipt_digest) = 71
                        AND substr(
                            offline_migration_receipt_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(offline_migration_receipt_digest) =
                            offline_migration_receipt_digest
                    )
                )
            );

            CREATE TABLE IF NOT EXISTS
                policy_authority_owner_contracts (
                    contract_id TEXT PRIMARY KEY,
                    schema_version BIGINT NOT NULL UNIQUE
                        REFERENCES policy_authority_schema_contracts(
                            schema_version
                        ) ON DELETE RESTRICT,
                    source_revision TEXT NOT NULL,
                    function_name TEXT NOT NULL UNIQUE,
                    function_definition_digest TEXT NOT NULL UNIQUE,
                    verifier_spki_digest TEXT NOT NULL,
                    verifier_measurement_digest TEXT NOT NULL,
                    verification_profile_digest TEXT NOT NULL UNIQUE,
                    response_max_bytes BIGINT NOT NULL,
                    response_max_age_ns BIGINT NOT NULL,
                    max_clock_skew_ns BIGINT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    CHECK (
                        contract_id =
                            'serverware.policyAuthorityOwnerContract/v2'
                    ),
                    CHECK (schema_version = 9),
                    CHECK (
                        source_revision =
                            'serverware.policyCandidateAuthoritySource/2026-07-30.351'
                    ),
                    CHECK (
                        function_name =
                            'serverware_policy_authority_execute_v9'
                    ),
                    CHECK (response_max_bytes = 75497472),
                    CHECK (response_max_age_ns = 30000000000),
                    CHECK (max_clock_skew_ns = 5000000000),
                    CHECK (
                        length(function_definition_digest) = 71
                        AND substr(
                            function_definition_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(function_definition_digest) =
                            function_definition_digest
                    ),
                    CHECK (
                        length(verifier_spki_digest) = 71
                        AND substr(verifier_spki_digest, 1, 7) = 'sha256:'
                        AND lower(verifier_spki_digest) =
                            verifier_spki_digest
                    ),
                    CHECK (
                        length(verifier_measurement_digest) = 71
                        AND substr(
                            verifier_measurement_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(verifier_measurement_digest) =
                            verifier_measurement_digest
                    ),
                    CHECK (
                        length(verification_profile_digest) = 71
                        AND substr(
                            verification_profile_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(verification_profile_digest) =
                            verification_profile_digest
                    )
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_verifier_capabilities (
                    capability_id TEXT PRIMARY KEY,
                    capability_digest TEXT NOT NULL UNIQUE,
                    operation_id TEXT NOT NULL UNIQUE,
                    operation TEXT NOT NULL,
                    request_digest TEXT NOT NULL UNIQUE,
                    authority_snapshot_before_digest TEXT NOT NULL,
                    mutation_plan_digest TEXT NOT NULL UNIQUE,
                    query_manifest_digest TEXT NOT NULL,
                    query_proofs_digest TEXT NOT NULL,
                    authority_root_set_digest TEXT NOT NULL,
                    result_digest TEXT NOT NULL,
                    response_digest TEXT NOT NULL UNIQUE,
                    verification_receipt_digest TEXT NOT NULL UNIQUE,
                    issuer_session_identity_digest TEXT NOT NULL,
                    executor_session_identity_digest TEXT NOT NULL,
                    issuer_measurement_digest TEXT NOT NULL,
                    issuer_attestation_receipt_digest TEXT NOT NULL,
                    issuer_credential_issuance_digest TEXT NOT NULL,
                    witness_reservation_digest TEXT NOT NULL UNIQUE,
                    witness_sequence BIGINT NOT NULL,
                    witness_head_digest TEXT NOT NULL,
                    deadline_monotonic_ns BIGINT NOT NULL,
                    fence BIGINT NOT NULL,
                    issued_monotonic_ns BIGINT NOT NULL,
                    issued_at_epoch_ns BIGINT NOT NULL,
                    expires_at_epoch_ns BIGINT NOT NULL,
                    status TEXT NOT NULL,
                    consumed_by_operation_id TEXT,
                    consumed_at_epoch_ns BIGINT,
                    CHECK (
                        operation IN (
                            'policy.activation.prepare',
                            'policy.activation.record-inclusion',
                            'policy.activation.finalize',
                            'policy.activation.abort',
                            'policy.genesis.prepare',
                            'policy.genesis.finalize',
                            'rbac.binding.mutate'
                        )
                    ),
                    CHECK (issued_at_epoch_ns >= 0),
                    CHECK (witness_sequence > 0),
                    CHECK (
                        witness_head_digest ~
                            '^sha256:[0-9a-f]{64}$'
                    ),
                    CHECK (deadline_monotonic_ns > issued_monotonic_ns),
                    CHECK (fence > 0),
                    CHECK (
                        status IN (
                            'issued', 'committed', 'expired', 'reconciled'
                        )
                    ),
                    CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                    CHECK (
                        (consumed_by_operation_id IS NULL
                            AND consumed_at_epoch_ns IS NULL)
                        OR (
                            consumed_by_operation_id = operation_id
                            AND consumed_at_epoch_ns >= issued_at_epoch_ns
                        )
                    )
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_fence_heads (
                    authority_scope TEXT PRIMARY KEY,
                    fence BIGINT NOT NULL,
                    witness_sequence BIGINT NOT NULL,
                    witness_head_digest TEXT NOT NULL,
                    updated_at_epoch_ns BIGINT NOT NULL,
                    CHECK (authority_scope = 'controlled-writer'),
                    CHECK (fence >= 0),
                    CHECK (witness_sequence >= 0),
                    CHECK (updated_at_epoch_ns >= 0)
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_writer_capabilities (
                    capability_id TEXT PRIMARY KEY,
                    capability_protocol TEXT NOT NULL DEFAULT 'v3',
                    capability_record_digest TEXT,
                    capability_digest TEXT NOT NULL UNIQUE,
                    envelope_id TEXT NOT NULL UNIQUE,
                    operation TEXT NOT NULL,
                    operation_id TEXT NOT NULL UNIQUE,
                    handler_name TEXT NOT NULL,
                    request_digest TEXT NOT NULL UNIQUE,
                    operation_manifest_digest TEXT NOT NULL,
                    query_manifest_digest TEXT NOT NULL,
                    authority_root_set_digest TEXT NOT NULL,
                    authority_snapshot_digest TEXT NOT NULL,
                    approver_policy_digest TEXT,
                    webauthn_receipt_json TEXT,
                    webauthn_receipt_digest TEXT,
                    webauthn_trust_high_water_digest TEXT,
                    witness_reservation_digest TEXT NOT NULL UNIQUE,
                    witness_sequence BIGINT NOT NULL,
                    witness_head_digest TEXT NOT NULL,
                    deadline_monotonic_ns BIGINT NOT NULL,
                    fence BIGINT NOT NULL,
                    issued_monotonic_ns BIGINT NOT NULL,
                    issued_at_epoch_ns BIGINT NOT NULL,
                    expires_at_epoch_ns BIGINT NOT NULL,
                    issuer_session_identity_digest TEXT NOT NULL,
                    issuer_measurement_digest TEXT NOT NULL,
                    issuer_attestation_receipt_digest TEXT NOT NULL,
                    issuer_credential_issuance_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    writer_token_digest TEXT UNIQUE,
                    reserved_at_epoch_ns BIGINT,
                    reserved_transaction_id BIGINT,
                    result_digest TEXT,
                    commit_receipt_digest TEXT UNIQUE,
                    committed_at_epoch_ns BIGINT,
                    failure_digest TEXT,
                    failed_at_epoch_ns BIGINT,
                    expected_result_digest TEXT NOT NULL,
                    planner_transaction_id TEXT NOT NULL UNIQUE,
                    authorization_projection_digest TEXT NOT NULL,
                    selected_business_rows_digest TEXT NOT NULL,
                    mutation_plan_digest TEXT NOT NULL,
                    deadline_epoch_ns BIGINT NOT NULL,
                    UNIQUE (capability_id, capability_protocol, capability_record_digest,
                            planner_transaction_id, envelope_id),
                    CHECK (capability_protocol IN ('v3', 'revocation-v4')),
                    CHECK (
                        (capability_protocol = 'v3' AND capability_record_digest IS NULL)
                        OR (capability_protocol = 'revocation-v4'
                            AND operation = 'webauthn.credential.revoke'
                            AND capability_record_digest IS NOT NULL
                            AND capability_record_digest ~ '^sha256:[0-9a-f]{64}$')
                    ),
                    CHECK (
                        status IN (
                            'issued', 'reserved', 'committed',
                            'expired', 'reconciled', 'failed'
                        )
                    ),
                    CHECK (witness_sequence > 0),
                    CHECK (
                        operation_manifest_digest ~
                            '^sha256:[0-9a-f]{64}$'
                        AND query_manifest_digest ~
                            '^sha256:[0-9a-f]{64}$'
                    ),
                    CHECK (
                        witness_head_digest ~
                            '^sha256:[0-9a-f]{64}$'
                    ),
                    CHECK (deadline_monotonic_ns > 0),
                    CHECK (fence > 0),
                    CHECK (issued_monotonic_ns > 0),
                    CHECK (deadline_monotonic_ns > issued_monotonic_ns),
                    CONSTRAINT
                        policy_authority_writer_capability_deadline_epoch
                    CHECK (deadline_epoch_ns > issued_at_epoch_ns),
                    CONSTRAINT
                        policy_authority_writer_capability_v9_digests
                    CHECK (
                        expected_result_digest ~
                            '^sha256:[0-9a-f]{64}$'
                        AND planner_transaction_id ~
                            '^sha256:[0-9a-f]{64}$'
                        AND authorization_projection_digest ~
                            '^sha256:[0-9a-f]{64}$'
                        AND selected_business_rows_digest ~
                            '^sha256:[0-9a-f]{64}$'
                        AND mutation_plan_digest ~
                            '^sha256:[0-9a-f]{64}$'
                    ),
                    CHECK (issued_at_epoch_ns >= 0),
                    CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                    CHECK (
                        (status = 'issued'
                            AND writer_token_digest IS NULL
                            AND reserved_at_epoch_ns IS NULL
                            AND reserved_transaction_id IS NULL
                            AND result_digest IS NULL
                            AND commit_receipt_digest IS NULL
                            AND committed_at_epoch_ns IS NULL
                            AND failure_digest IS NULL
                            AND failed_at_epoch_ns IS NULL)
                        OR (
                            status = 'reserved'
                            AND writer_token_digest IS NOT NULL
                            AND reserved_at_epoch_ns IS NOT NULL
                            AND reserved_transaction_id IS NOT NULL
                            AND result_digest IS NULL
                            AND commit_receipt_digest IS NULL
                            AND committed_at_epoch_ns IS NULL
                            AND failure_digest IS NULL
                            AND failed_at_epoch_ns IS NULL
                        )
                        OR (
                            status IN ('committed', 'reconciled')
                            AND writer_token_digest IS NOT NULL
                            AND reserved_at_epoch_ns IS NOT NULL
                            AND reserved_transaction_id IS NOT NULL
                            AND result_digest IS NOT NULL
                            AND commit_receipt_digest IS NOT NULL
                            AND committed_at_epoch_ns IS NOT NULL
                            AND failure_digest IS NULL
                            AND failed_at_epoch_ns IS NULL
                        )
                        OR (
                            status = 'expired'
                            AND result_digest IS NULL
                            AND commit_receipt_digest IS NULL
                            AND committed_at_epoch_ns IS NULL
                            AND failure_digest IS NULL
                            AND failed_at_epoch_ns IS NULL
                        )
                        OR (
                            status = 'failed'
                            AND writer_token_digest IS NULL
                            AND reserved_at_epoch_ns IS NULL
                            AND reserved_transaction_id IS NULL
                            AND result_digest IS NULL
                            AND commit_receipt_digest IS NULL
                            AND committed_at_epoch_ns IS NULL
                            AND failure_digest ~
                                '^sha256:[0-9a-f]{64}$'
                            AND failed_at_epoch_ns IS NOT NULL
                        )
                    )
                );

            CREATE INDEX IF NOT EXISTS
                policy_authority_writer_capabilities_fence
                ON policy_authority_writer_capabilities (
                    fence, status, expires_at_epoch_ns
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_consumed_envelopes (
                    envelope_id TEXT PRIMARY KEY,
                    parent_envelope_id TEXT,
                    purpose TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    deadline_monotonic_ns BIGINT NOT NULL,
                    fence BIGINT NOT NULL,
                    consumed_at_epoch_ns BIGINT NOT NULL,
                    witness_receipt_digest TEXT NOT NULL,
                    UNIQUE (purpose, request_digest, fence),
                    CHECK (deadline_monotonic_ns > 0),
                    CHECK (fence > 0),
                    CHECK (consumed_at_epoch_ns >= 0)
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_writer_receipts (
                    commit_receipt_digest TEXT PRIMARY KEY,
                    capability_id TEXT NOT NULL UNIQUE,
                    envelope_id TEXT NOT NULL UNIQUE,
                    operation TEXT NOT NULL,
                    handler_name TEXT NOT NULL,
                    request_digest TEXT NOT NULL UNIQUE,
                    result_json TEXT NOT NULL,
                    result_digest TEXT NOT NULL,
                    authority_root_set_before_digest TEXT NOT NULL,
                    authority_root_set_after_digest TEXT NOT NULL,
                    operation_manifest_digest TEXT NOT NULL,
                    query_manifest_digest TEXT NOT NULL,
                    witness_reservation_digest TEXT NOT NULL,
                    witness_sequence BIGINT NOT NULL,
                    deadline_monotonic_ns BIGINT NOT NULL,
                    fence BIGINT NOT NULL,
                    committed_at_epoch_ns BIGINT NOT NULL,
                    source_revision TEXT NOT NULL,
                    CHECK (length(result_json) BETWEEN 2 AND 67108864),
                    CHECK (
                        operation_manifest_digest ~
                            '^sha256:[0-9a-f]{64}$'
                        AND query_manifest_digest ~
                            '^sha256:[0-9a-f]{64}$'
                    ),
                    CHECK (witness_sequence > 0),
                    CHECK (deadline_monotonic_ns > 0),
                    CHECK (fence > 0),
                    CHECK (committed_at_epoch_ns >= 0),
                    CHECK (
                        source_revision =
                        'serverware.policyCandidateAuthoritySource/2026-07-30.351'
                    )
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_webauthn_assertion_receipts (
                    assertion_receipt_digest TEXT PRIMARY KEY,
                    capability_id TEXT NOT NULL UNIQUE,
                    operation_id TEXT NOT NULL UNIQUE,
                    operation TEXT NOT NULL,
                    request_digest TEXT NOT NULL UNIQUE,
                    challenge_id TEXT NOT NULL UNIQUE,
                    credential_record_id TEXT NOT NULL,
                    credential_id TEXT NOT NULL,
                    credential_policy_digest TEXT NOT NULL,
                    trust_high_water_digest TEXT NOT NULL,
                    client_data_json_digest TEXT NOT NULL,
                    authenticator_data_digest TEXT NOT NULL,
                    signature_digest TEXT NOT NULL,
                    flags BIGINT NOT NULL,
                    prior_counter BIGINT NOT NULL,
                    counter BIGINT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    verified_at_epoch_ns BIGINT NOT NULL,
                    CHECK (flags >= 0),
                    CHECK (prior_counter >= 0),
                    CHECK (counter > prior_counter),
                    CHECK (length(receipt_json) BETWEEN 2 AND 4194304),
                    CHECK (verified_at_epoch_ns >= 0)
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_external_witness_receipts (
                    witness_receipt_digest TEXT PRIMARY KEY,
                    witness_identity_digest TEXT NOT NULL,
                    witness_sequence BIGINT NOT NULL UNIQUE,
                    witness_head_digest TEXT NOT NULL UNIQUE,
                    predecessor_head_digest TEXT,
                    predecessor_receipt_digest TEXT,
                    log_predecessor_head_digest TEXT,
                    phase TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    capability_id TEXT,
                    result_digest TEXT,
                    fence BIGINT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    recorded_at_epoch_ns BIGINT NOT NULL,
                    CHECK (
                        phase IN (
                            'reserve', 'commit', 'abort', 'reconcile',
                            'webauthn-trust-publish'
                        )
                    ),
                    CHECK (witness_sequence > 0),
                    CHECK (fence > 0),
                    CHECK (length(receipt_json) BETWEEN 2 AND 4194304),
                    CHECK (recorded_at_epoch_ns >= 0)
                );

            CREATE TABLE IF NOT EXISTS
                webauthn_trust_publication_high_water (
                    authority_scope TEXT PRIMARY KEY,
                    rollback_epoch BIGINT NOT NULL,
                    publication_sequence BIGINT NOT NULL,
                    publication_digest TEXT NOT NULL,
                    metadata_blob_digest TEXT NOT NULL,
                    revocation_set_digest TEXT NOT NULL,
                    witness_receipt_digest TEXT NOT NULL,
                    witness_sequence BIGINT NOT NULL,
                    updated_at_epoch_ns BIGINT NOT NULL,
                    CHECK (authority_scope = 'webauthn-metadata'),
                    CHECK (rollback_epoch >= 0),
                    CHECK (publication_sequence > 0),
                    CHECK (witness_sequence > 0),
                    CHECK (updated_at_epoch_ns >= 0)
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_query_dependency_manifests (
                    operation TEXT NOT NULL,
                    ordinal BIGINT NOT NULL,
                    predicate_id TEXT NOT NULL UNIQUE,
                    table_name TEXT NOT NULL,
                    handler_digest TEXT NOT NULL,
                    key_columns_json TEXT NOT NULL,
                    write_access BIGINT NOT NULL,
                    index_contract TEXT NOT NULL,
                    predicate_kind TEXT NOT NULL,
                    selector_source TEXT NOT NULL,
                    selector_paths_json TEXT NOT NULL,
                    proof_kind TEXT NOT NULL,
                    exact_absence BIGINT NOT NULL,
                    maximum_rows BIGINT NOT NULL,
                    entry_digest TEXT NOT NULL UNIQUE,
                    manifest_digest TEXT NOT NULL,
                    source_revision TEXT NOT NULL,
                    PRIMARY KEY (operation, ordinal),
                    CHECK (ordinal > 0),
                    CHECK (write_access IN (0, 1)),
                    CHECK (exact_absence = 1),
                    CHECK (maximum_rows BETWEEN 1 AND 128),
                    CHECK (
                        predicate_kind =
                            'relation-root-and-explicit-key-set'
                        AND index_contract =
                            'incremental-authenticated-relation-root-v3'
                    ),
                    CHECK (
                        selector_source =
                            'closed-operation-argument-path-v1'
                    ),
                    CHECK (
                        length(selector_paths_json) BETWEEN 2 AND 65536
                    ),
                    CHECK (
                        proof_kind =
                        'radix16-canonical-multiproof-v2'
                    ),
                    CHECK (
                        source_revision =
                        'serverware.policyCandidateAuthoritySource/2026-07-30.351'
                    )
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_authenticated_table_roots (
                    table_name TEXT PRIMARY KEY,
                    root_revision BIGINT NOT NULL,
                    root_digest TEXT NOT NULL,
                    leaf_count BIGINT NOT NULL,
                    tree_depth BIGINT NOT NULL,
                    tree_radix BIGINT NOT NULL,
                    manifest_digest TEXT NOT NULL,
                    updated_at_epoch_ns BIGINT NOT NULL,
                    CHECK (root_revision >= 0),
                    CHECK (leaf_count >= 0),
                    CHECK (tree_depth = 64),
                    CHECK (tree_radix = 16),
                    CHECK (updated_at_epoch_ns >= 0)
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_authenticated_tree_nodes (
                    table_name TEXT NOT NULL,
                    depth BIGINT NOT NULL,
                    path_prefix TEXT NOT NULL,
                    node_digest TEXT NOT NULL,
                    root_revision BIGINT NOT NULL,
                    PRIMARY KEY (table_name, depth, path_prefix),
                    CHECK (depth BETWEEN 0 AND 64),
                    CHECK (length(path_prefix) = depth),
                    CHECK (root_revision > 0)
                );

            CREATE INDEX IF NOT EXISTS
                policy_authority_authenticated_tree_nodes_lookup
                ON policy_authority_authenticated_tree_nodes (
                    table_name, depth, path_prefix, node_digest
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_authenticated_leaves (
                    table_name TEXT NOT NULL,
                    key_digest TEXT NOT NULL,
                    key_json TEXT NOT NULL,
                    row_digest TEXT NOT NULL,
                    leaf_digest TEXT NOT NULL,
                    root_revision BIGINT NOT NULL,
                    PRIMARY KEY (table_name, key_digest),
                    UNIQUE (table_name, key_json),
                    CHECK (root_revision > 0)
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_authenticated_root_revisions (
                    table_name TEXT NOT NULL,
                    root_revision BIGINT NOT NULL,
                    previous_root_digest TEXT NOT NULL,
                    root_digest TEXT NOT NULL,
                    leaf_count BIGINT NOT NULL,
                    mutation_operation TEXT NOT NULL,
                    mutation_key_digest TEXT NOT NULL,
                    mutation_row_digest TEXT,
                    transaction_id TEXT NOT NULL,
                    committed_at_epoch_ns BIGINT NOT NULL,
                    PRIMARY KEY (table_name, root_revision),
                    CHECK (root_revision > 0),
                    CHECK (leaf_count >= 0),
                    CHECK (
                        mutation_operation IN (
                            'INSERT', 'UPDATE', 'DELETE'
                        )
                    ),
                    CHECK (committed_at_epoch_ns >= 0)
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_owner_operations (
                    operation_id TEXT PRIMARY KEY,
                    operation_sequence BIGINT NOT NULL UNIQUE,
                    operation TEXT NOT NULL,
                    request_digest TEXT NOT NULL UNIQUE,
                    verifier_response_digest TEXT NOT NULL UNIQUE,
                    result_digest TEXT NOT NULL,
                    mutation_plan_digest TEXT NOT NULL UNIQUE,
                    query_manifest_digest TEXT NOT NULL,
                    query_proofs_digest TEXT NOT NULL,
                    authority_root_set_before_digest TEXT NOT NULL,
                    authority_root_set_after_digest TEXT NOT NULL,
                    authority_snapshot_before_digest TEXT NOT NULL,
                    authority_snapshot_after_digest TEXT NOT NULL,
                    verifier_capability_id TEXT NOT NULL UNIQUE
                        REFERENCES policy_authority_verifier_capabilities(
                            capability_id
                        ) ON DELETE RESTRICT,
                    verifier_session_identity_digest TEXT NOT NULL,
                    verifier_attestation_receipt_digest TEXT NOT NULL,
                    verifier_credential_issuance_digest TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    response_digest TEXT NOT NULL UNIQUE,
                    committed_at_epoch_ns BIGINT NOT NULL,
                    source_revision TEXT NOT NULL,
                    CHECK (operation_sequence > 0),
                    CHECK (
                        operation IN (
                            'policy.activation.prepare',
                            'policy.activation.record-inclusion',
                            'policy.activation.finalize',
                            'policy.activation.abort',
                            'policy.genesis.prepare',
                            'policy.genesis.finalize',
                            'rbac.binding.mutate'
                        )
                    ),
                    CHECK (committed_at_epoch_ns >= 0),
                    CHECK (
                        source_revision =
                            'serverware.policyCandidateAuthoritySource/2026-07-30.351'
                    ),
                    CHECK (
                        length(response_json) BETWEEN 2 AND 75497472
                    ),
                    CHECK (
                        length(operation_id) = 71
                        AND substr(operation_id, 1, 7) = 'sha256:'
                        AND lower(operation_id) = operation_id
                    ),
                    CHECK (
                        length(request_digest) = 71
                        AND substr(request_digest, 1, 7) = 'sha256:'
                        AND lower(request_digest) = request_digest
                    ),
                    CHECK (
                        length(verifier_response_digest) = 71
                        AND substr(
                            verifier_response_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(verifier_response_digest) =
                            verifier_response_digest
                    ),
                    CHECK (
                        length(result_digest) = 71
                        AND substr(result_digest, 1, 7) = 'sha256:'
                        AND lower(result_digest) = result_digest
                    ),
                    CHECK (
                        length(mutation_plan_digest) = 71
                        AND substr(mutation_plan_digest, 1, 7) = 'sha256:'
                        AND lower(mutation_plan_digest) =
                            mutation_plan_digest
                    ),
                    CHECK (
                        length(query_manifest_digest) = 71
                        AND substr(query_manifest_digest, 1, 7) =
                            'sha256:'
                        AND lower(query_manifest_digest) =
                            query_manifest_digest
                    ),
                    CHECK (
                        length(query_proofs_digest) = 71
                        AND substr(query_proofs_digest, 1, 7) =
                            'sha256:'
                        AND lower(query_proofs_digest) =
                            query_proofs_digest
                    ),
                    CHECK (
                        length(authority_root_set_before_digest) = 71
                        AND substr(
                            authority_root_set_before_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(authority_root_set_before_digest) =
                            authority_root_set_before_digest
                    ),
                    CHECK (
                        length(authority_root_set_after_digest) = 71
                        AND substr(
                            authority_root_set_after_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(authority_root_set_after_digest) =
                            authority_root_set_after_digest
                    ),
                    CHECK (
                        length(authority_snapshot_before_digest) = 71
                        AND substr(
                            authority_snapshot_before_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(authority_snapshot_before_digest) =
                            authority_snapshot_before_digest
                    ),
                    CHECK (
                        length(authority_snapshot_after_digest) = 71
                        AND substr(
                            authority_snapshot_after_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(authority_snapshot_after_digest) =
                            authority_snapshot_after_digest
                    ),
                    CHECK (
                        length(verifier_session_identity_digest) = 71
                        AND substr(
                            verifier_session_identity_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(verifier_session_identity_digest) =
                            verifier_session_identity_digest
                    ),
                    CHECK (
                        length(verifier_attestation_receipt_digest) = 71
                        AND substr(
                            verifier_attestation_receipt_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(verifier_attestation_receipt_digest) =
                            verifier_attestation_receipt_digest
                    ),
                    CHECK (
                        length(verifier_credential_issuance_digest) = 71
                        AND substr(
                            verifier_credential_issuance_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(verifier_credential_issuance_digest) =
                            verifier_credential_issuance_digest
                    ),
                    CHECK (
                        length(response_digest) = 71
                        AND substr(response_digest, 1, 7) = 'sha256:'
                        AND lower(response_digest) = response_digest
                    )
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_owner_decisions (
                    verifier_response_digest TEXT PRIMARY KEY,
                    decision_sequence BIGINT NOT NULL UNIQUE,
                    operation_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    authority_snapshot_digest TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    result_digest TEXT NOT NULL,
                    verification_receipt_digest TEXT NOT NULL,
                    verifier_spki_digest TEXT NOT NULL,
                    verifier_measurement_digest TEXT NOT NULL,
                    verifier_attestation_receipt_digest TEXT NOT NULL,
                    verifier_credential_issuance_digest TEXT NOT NULL,
                    signature_digest TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    response_digest TEXT NOT NULL UNIQUE,
                    committed_at_epoch_ns BIGINT NOT NULL,
                    source_revision TEXT NOT NULL,
                    CHECK (decision_sequence > 0),
                    CHECK (
                        operation IN (
                            'policy.activation.prepare',
                            'policy.activation.record-inclusion',
                            'policy.activation.finalize',
                            'policy.activation.abort',
                            'policy.genesis.prepare',
                            'policy.genesis.finalize',
                            'rbac.binding.mutate'
                        )
                    ),
                    CHECK (decision IN ('denied', 'unknown')),
                    CHECK (committed_at_epoch_ns >= 0),
                    CHECK (
                        source_revision =
                            'serverware.policyCandidateAuthoritySource/2026-07-30.351'
                    ),
                    CHECK (
                        length(response_json) BETWEEN 2 AND 75497472
                    )
                );
            CREATE INDEX IF NOT EXISTS
                policy_authority_owner_decisions_operation
                ON policy_authority_owner_decisions (
                    operation_id, decision_sequence
                );

            CREATE TABLE IF NOT EXISTS policy_authority_trusted_keys (
                evidence_kind TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                key_revision BIGINT NOT NULL,
                signature_domain TEXT NOT NULL,
                public_key_base64url TEXT NOT NULL,
                public_key_digest TEXT NOT NULL,
                trust_receipt_digest TEXT NOT NULL UNIQUE,
                trust_receipt_json TEXT NOT NULL,
                trust_receipt_payload_digest TEXT NOT NULL UNIQUE,
                trust_receipt_signature_digest TEXT NOT NULL UNIQUE,
                not_before_epoch_ns BIGINT NOT NULL,
                not_after_epoch_ns BIGINT NOT NULL,
                max_clock_skew_ns BIGINT NOT NULL,
                max_evidence_age_ns BIGINT NOT NULL,
                installed_by TEXT NOT NULL,
                installed_at_epoch_ns BIGINT NOT NULL,
                PRIMARY KEY (evidence_kind, key_revision),
                UNIQUE (evidence_kind, signing_key_id),
                UNIQUE (
                    evidence_kind, signing_key_id, public_key_digest
                ),
                UNIQUE (
                    evidence_kind, key_revision, signing_key_id,
                    public_key_digest
                ),
                UNIQUE (
                    evidence_kind, signing_key_id, signature_domain,
                    public_key_digest
                ),
                UNIQUE (
                    evidence_kind, key_revision, signing_key_id,
                    signature_domain, public_key_digest
                ),
                CHECK (
                    (evidence_kind = 'candidate_artifact'
                        AND signature_domain =
                            'serverware.policyCandidateArtifact/v2')
                    OR (evidence_kind = 'canary_assignment'
                        AND signature_domain =
                            'serverware.policyShadowAssignment/v1')
                    OR (evidence_kind = 'canary_state'
                        AND signature_domain =
                            'serverware.policyCanaryState/v2')
                    OR (evidence_kind = 'runtime_attestation'
                        AND signature_domain =
                            'serverware.policyRuntimeAttestation/v2')
                    OR (
                        evidence_kind = 'shadow_role_authorization'
                        AND signature_domain =
                            'serverware.policyShadowRoleAuthorization/v1'
                    )
                    OR (
                        evidence_kind = 'generation_publication'
                        AND signature_domain =
                            'serverware.policyShadowGenerationPublication/v2'
                    )
                    OR (
                        evidence_kind =
                            'generation_runtime_attestation_verification'
                        AND signature_domain =
                            'serverware.policyShadowRuntimeAttestationVerification/v2'
                    )
                    OR (evidence_kind = 'runtime_role_revocation'
                        AND signature_domain =
                            'serverware.policyRuntimeRoleKeyRevocation/v1')
                    OR (evidence_kind = 'compiler_analysis'
                        AND signature_domain =
                            'serverware.policyAuthorityAnalysis/v1')
                    OR (evidence_kind = 'readiness'
                        AND signature_domain =
                            'serverware.policyActivationReadiness/v2')
                    OR (evidence_kind = 'activation_state'
                        AND signature_domain =
                            'serverware.policyActivationState/v2')
                    OR (evidence_kind = 'publication_receipt'
                        AND signature_domain =
                            'serverware.policyPublicationReceipt/v2')
                    OR (evidence_kind = 'rollback_authority'
                        AND signature_domain =
                            'serverware.policyRollbackAuthority/v2')
                    OR (
                        evidence_kind =
                            'rollback_authority_revocation'
                        AND signature_domain =
                            'serverware.policyRollbackAuthorityRevocation/v1'
                    )
                    OR (
                        evidence_kind = 'audit_inclusion_receipt'
                        AND signature_domain =
                            'serverware.policyAuthorityAuditInclusion/v1'
                    )
                    OR (
                        evidence_kind = 'authority_genesis'
                        AND signature_domain =
                            'serverware.policyAuthorityGenesis/v1'
                    )
                ),
                CHECK (key_revision > 0),
                CHECK (signing_key_id = public_key_digest),
                CHECK (length(signing_key_id) BETWEEN 1 AND 1024),
                CHECK (length(public_key_base64url) = 43),
                CHECK (length(trust_receipt_json) BETWEEN 2 AND 1048576),
                CHECK (not_before_epoch_ns >= 0),
                CHECK (not_after_epoch_ns > not_before_epoch_ns),
                CHECK (max_clock_skew_ns BETWEEN 0 AND 300000000000),
                CHECK (max_evidence_age_ns BETWEEN 1 AND 31536000000000000),
                CHECK (
                    installed_at_epoch_ns >= not_before_epoch_ns
                    AND installed_at_epoch_ns <= not_after_epoch_ns
                ),
                CHECK (length(installed_by) BETWEEN 1 AND 1024),
                CHECK (
                    length(public_key_digest) = 71
                    AND substr(public_key_digest, 1, 7) = 'sha256:'
                    AND lower(public_key_digest) = public_key_digest
                ),
                CHECK (
                    length(trust_receipt_digest) = 71
                    AND substr(trust_receipt_digest, 1, 7) = 'sha256:'
                    AND lower(trust_receipt_digest) = trust_receipt_digest
                ),
                CHECK (
                    length(trust_receipt_payload_digest) = 71
                    AND substr(
                        trust_receipt_payload_digest, 1, 7
                    ) = 'sha256:'
                    AND lower(trust_receipt_payload_digest) =
                        trust_receipt_payload_digest
                ),
                CHECK (
                    length(trust_receipt_signature_digest) = 71
                    AND substr(
                        trust_receipt_signature_digest, 1, 7
                    ) = 'sha256:'
                    AND lower(trust_receipt_signature_digest) =
                        trust_receipt_signature_digest
                )
            );

            CREATE TABLE IF NOT EXISTS policy_authority_trusted_key_revocations (
                evidence_kind TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                key_revision BIGINT NOT NULL,
                public_key_digest TEXT NOT NULL,
                revocation_sequence BIGINT NOT NULL UNIQUE,
                revocation_digest TEXT NOT NULL UNIQUE,
                revocation_receipt_json TEXT NOT NULL,
                revocation_receipt_payload_digest TEXT NOT NULL UNIQUE,
                revocation_receipt_signature_digest TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                revoked_by TEXT NOT NULL,
                revoked_at_epoch_ns BIGINT NOT NULL,
                PRIMARY KEY (evidence_kind, signing_key_id),
                FOREIGN KEY (
                    evidence_kind, key_revision, signing_key_id,
                    public_key_digest
                ) REFERENCES policy_authority_trusted_keys (
                    evidence_kind, key_revision, signing_key_id,
                    public_key_digest
                ) ON DELETE RESTRICT,
                CHECK (key_revision > 0),
                CHECK (signing_key_id = public_key_digest),
                CHECK (revocation_sequence > 0),
                CHECK (revoked_at_epoch_ns >= 0),
                CHECK (
                    length(revocation_receipt_json) BETWEEN 2 AND 1048576
                ),
                CHECK (length(reason) BETWEEN 1 AND 4096),
                CHECK (length(revoked_by) BETWEEN 1 AND 1024),
                CHECK (
                    length(revocation_digest) = 71
                    AND substr(revocation_digest, 1, 7) = 'sha256:'
                    AND lower(revocation_digest) = revocation_digest
                ),
                CHECK (
                    length(revocation_receipt_payload_digest) = 71
                    AND substr(
                        revocation_receipt_payload_digest, 1, 7
                    ) = 'sha256:'
                    AND lower(revocation_receipt_payload_digest) =
                        revocation_receipt_payload_digest
                ),
                CHECK (
                    length(revocation_receipt_signature_digest) = 71
                    AND substr(
                        revocation_receipt_signature_digest, 1, 7
                    ) = 'sha256:'
                    AND lower(revocation_receipt_signature_digest) =
                        revocation_receipt_signature_digest
                )
            );

            CREATE TABLE IF NOT EXISTS policy_authority_trusted_key_heads (
                evidence_kind TEXT PRIMARY KEY,
                head_key_revision BIGINT NOT NULL,
                head_signing_key_id TEXT NOT NULL,
                head_public_key_digest TEXT NOT NULL,
                updated_at_epoch_ns BIGINT NOT NULL,
                FOREIGN KEY (
                    evidence_kind, head_key_revision, head_signing_key_id,
                    head_public_key_digest
                ) REFERENCES policy_authority_trusted_keys (
                    evidence_kind, key_revision, signing_key_id,
                    public_key_digest
                ) ON DELETE RESTRICT,
                UNIQUE (evidence_kind, head_key_revision),
                CHECK (head_signing_key_id = head_public_key_digest),
                CHECK (head_key_revision > 0),
                CHECK (updated_at_epoch_ns >= 0)
            );

            CREATE TABLE IF NOT EXISTS policy_authority_evidence_verifications (
                verification_receipt_digest TEXT PRIMARY KEY,
                evidence_kind TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature_domain TEXT NOT NULL,
                public_key_digest TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                record_binding_digest TEXT NOT NULL UNIQUE,
                envelope_digest TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                signature_message_digest TEXT NOT NULL UNIQUE,
                trusted_key_revision BIGINT NOT NULL,
                trusted_key_installed_at_epoch_ns BIGINT NOT NULL,
                trusted_key_revocation_sequence BIGINT NOT NULL,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                verified_at_epoch_ns BIGINT NOT NULL,
                UNIQUE (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ),
                FOREIGN KEY (
                    evidence_kind, trusted_key_revision, signing_key_id,
                    signature_domain, public_key_digest
                ) REFERENCES policy_authority_trusted_keys (
                    evidence_kind, key_revision, signing_key_id,
                    signature_domain, public_key_digest
                ) ON DELETE RESTRICT,
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (signing_key_id = public_key_digest),
                CHECK (trusted_key_revision > 0),
                CHECK (trusted_key_installed_at_epoch_ns >= 0),
                CHECK (trusted_key_revocation_sequence >= 0),
                CHECK (issued_at_epoch_ns >= 0),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (
                    verified_at_epoch_ns >= 0
                    AND verified_at_epoch_ns < expires_at_epoch_ns
                ),
                CHECK (length(signature) = 86),
                CHECK (
                    length(verification_receipt_digest) = 71
                    AND substr(
                        verification_receipt_digest, 1, 7
                    ) = 'sha256:'
                    AND lower(verification_receipt_digest) =
                        verification_receipt_digest
                ),
                CHECK (
                    length(signature_digest) = 71
                    AND substr(signature_digest, 1, 7) = 'sha256:'
                    AND lower(signature_digest) = signature_digest
                ),
                CHECK (
                    length(record_binding_digest) = 71
                    AND substr(record_binding_digest, 1, 7) = 'sha256:'
                    AND lower(record_binding_digest) = record_binding_digest
                ),
                CHECK (
                    length(envelope_digest) = 71
                    AND substr(envelope_digest, 1, 7) = 'sha256:'
                    AND lower(envelope_digest) = envelope_digest
                ),
                CHECK (
                    length(payload_digest) = 71
                    AND substr(payload_digest, 1, 7) = 'sha256:'
                    AND lower(payload_digest) = payload_digest
                ),
                CHECK (
                    length(signature_message_digest) = 71
                    AND substr(signature_message_digest, 1, 7) = 'sha256:'
                    AND lower(signature_message_digest) =
                        signature_message_digest
                )
            );

            CREATE TABLE IF NOT EXISTS policy_authority_transition_audits (
                transition_digest TEXT PRIMARY KEY,
                outbox_id TEXT NOT NULL UNIQUE,
                outbox_event_json TEXT NOT NULL,
                outbox_event_digest TEXT NOT NULL,
                event_type TEXT NOT NULL,
                entity_kind TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                entity_revision BIGINT NOT NULL,
                state_digest TEXT NOT NULL,
                previous_state_digest TEXT,
                event_payload_digest TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                created_at_epoch_ns BIGINT NOT NULL,
                UNIQUE (
                    transition_digest, entity_kind, entity_id, entity_revision,
                    state_digest, previous_state_digest, event_type
                ),
                UNIQUE (entity_kind, entity_id, entity_revision),
                FOREIGN KEY (outbox_id, outbox_event_digest)
                    REFERENCES metadata_audit_outbox(id, event_digest)
                    ON DELETE RESTRICT,
                CHECK (
                    entity_kind IN (
                        'candidate_artifact', 'canary', 'canary_assignment',
                        'canary_instance', 'load_receipt',
                        'shadow_runtime_attestation_handoff',
                        'shadow_generation_publication',
                        'custody_evidence', 'checkpoint',
                        'readiness', 'activation_approval', 'activation',
                        'publication_receipt', 'trusted_key',
                        'trusted_key_revocation',
                        'runtime_role_key_revocation',
                        'rollback_authority_revocation',
                        'activation_abort', 'activation_genesis',
                        'rbac_binding'
                    )
                ),
                CHECK (entity_revision > 0),
                CHECK (created_at_epoch_ns >= 0),
                CHECK (length(event_type) BETWEEN 1 AND 256),
                CHECK (length(entity_id) BETWEEN 1 AND 1024),
                CHECK (length(actor_id) BETWEEN 1 AND 1024),
                CHECK (
                    length(transition_digest) = 71
                    AND substr(transition_digest, 1, 7) = 'sha256:'
                    AND lower(transition_digest) = transition_digest
                ),
                CHECK (
                    length(state_digest) = 71
                    AND substr(state_digest, 1, 7) = 'sha256:'
                    AND lower(state_digest) = state_digest
                ),
                CHECK (
                    previous_state_digest IS NULL
                    OR (
                        length(previous_state_digest) = 71
                        AND substr(previous_state_digest, 1, 7) = 'sha256:'
                        AND lower(previous_state_digest) = previous_state_digest
                    )
                ),
                CHECK (
                    length(event_payload_digest) = 71
                    AND substr(event_payload_digest, 1, 7) = 'sha256:'
                    AND lower(event_payload_digest) = event_payload_digest
                )
                ,
                CHECK (
                    length(outbox_event_digest) = 71
                    AND substr(outbox_event_digest, 1, 7) = 'sha256:'
                    AND lower(outbox_event_digest) = outbox_event_digest
                ),
                CHECK (length(outbox_event_json) BETWEEN 2 AND 8388608)
            );

            CREATE TABLE IF NOT EXISTS
                policy_authority_audit_inclusion_receipts (
                    inclusion_receipt_envelope_digest TEXT PRIMARY KEY,
                    inclusion_receipt_payload_digest TEXT NOT NULL UNIQUE,
                    transition_digest TEXT NOT NULL UNIQUE
                        REFERENCES policy_authority_transition_audits(
                            transition_digest
                        ) ON DELETE RESTRICT,
                    outbox_id TEXT NOT NULL UNIQUE,
                    outbox_event_digest TEXT NOT NULL,
                    audit_store_identity_digest TEXT NOT NULL,
                    audit_ledger_namespace TEXT NOT NULL,
                    audit_signer_public_key_digest TEXT NOT NULL,
                    audit_event_hash TEXT NOT NULL UNIQUE,
                    audit_sequence BIGINT NOT NULL,
                    previous_audit_event_hash TEXT,
                    inclusion_root_digest TEXT NOT NULL,
                    inclusion_receipt_envelope_json TEXT NOT NULL,
                    inclusion_receipt_payload_json TEXT NOT NULL,
                    signature_algorithm TEXT NOT NULL,
                    signing_key_id TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    signature_digest TEXT NOT NULL UNIQUE,
                    evidence_kind TEXT NOT NULL
                        DEFAULT 'audit_inclusion_receipt',
                    record_binding_digest TEXT NOT NULL UNIQUE,
                    verification_receipt_digest TEXT NOT NULL UNIQUE,
                    issued_at_epoch_ns BIGINT NOT NULL,
                    expires_at_epoch_ns BIGINT NOT NULL,
                    verified_at_epoch_ns BIGINT NOT NULL,
                    UNIQUE (
                        audit_store_identity_digest, audit_ledger_namespace,
                        audit_sequence, audit_event_hash,
                        inclusion_root_digest
                    ),
                    FOREIGN KEY (
                        outbox_id, outbox_event_digest
                    ) REFERENCES metadata_audit_outbox(
                        id, event_digest
                    ) ON DELETE RESTRICT,
                    FOREIGN KEY (
                        verification_receipt_digest, evidence_kind,
                        signing_key_id, signature_digest,
                        record_binding_digest
                    ) REFERENCES policy_authority_evidence_verifications (
                        verification_receipt_digest, evidence_kind,
                        signing_key_id, signature_digest,
                        record_binding_digest
                    ) ON DELETE RESTRICT,
                    CHECK (
                        evidence_kind = 'audit_inclusion_receipt'
                    ),
                    CHECK (signature_algorithm = 'Ed25519'),
                    CHECK (
                        audit_ledger_namespace =
                            'serverware.policy-authority'
                    ),
                    CHECK (
                        signing_key_id =
                            audit_signer_public_key_digest
                    ),
                    CHECK (audit_sequence > 0),
                    CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                    CHECK (
                        verified_at_epoch_ns >= issued_at_epoch_ns
                        AND verified_at_epoch_ns < expires_at_epoch_ns
                    ),
                    CHECK (
                        length(inclusion_receipt_envelope_json)
                        BETWEEN 2 AND 1048576
                    ),
                    CHECK (
                        length(inclusion_receipt_payload_json)
                        BETWEEN 2 AND 1048576
                    )
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_audit_inclusion_heads (
                    audit_store_identity_digest TEXT PRIMARY KEY,
                    audit_ledger_namespace TEXT NOT NULL,
                    audit_signer_public_key_digest TEXT NOT NULL,
                    signing_key_id TEXT NOT NULL,
                    audit_sequence BIGINT NOT NULL,
                    audit_event_hash TEXT NOT NULL,
                    inclusion_root_digest TEXT NOT NULL,
                    inclusion_receipt_envelope_digest TEXT NOT NULL,
                    updated_at_epoch_ns BIGINT NOT NULL,
                    FOREIGN KEY (
                        audit_store_identity_digest,
                        audit_ledger_namespace,
                        audit_sequence, audit_event_hash,
                        inclusion_root_digest
                    ) REFERENCES policy_authority_audit_inclusion_receipts (
                        audit_store_identity_digest,
                        audit_ledger_namespace,
                        audit_sequence, audit_event_hash,
                        inclusion_root_digest
                    ) ON DELETE RESTRICT,
                    FOREIGN KEY (
                        inclusion_receipt_envelope_digest
                    ) REFERENCES policy_authority_audit_inclusion_receipts (
                        inclusion_receipt_envelope_digest
                    ) ON DELETE RESTRICT,
                    CHECK (
                        audit_ledger_namespace =
                            'serverware.policy-authority'
                    ),
                    CHECK (
                        signing_key_id =
                            audit_signer_public_key_digest
                    ),
                    CHECK (audit_sequence > 0),
                    CHECK (updated_at_epoch_ns >= 0)
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_genesis_preparations (
                    genesis_preparation_digest TEXT PRIMARY KEY,
                    policy_id TEXT NOT NULL,
                    policy_sequence BIGINT NOT NULL,
                    rollback_epoch BIGINT NOT NULL,
                    policy_hash TEXT NOT NULL UNIQUE,
                    high_water_digest TEXT NOT NULL UNIQUE,
                    genesis_envelope_json TEXT NOT NULL,
                    genesis_envelope_digest TEXT NOT NULL UNIQUE,
                    genesis_payload_json TEXT NOT NULL,
                    genesis_payload_digest TEXT NOT NULL UNIQUE,
                    signature_algorithm TEXT NOT NULL,
                    signing_key_id TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    signature_digest TEXT NOT NULL UNIQUE,
                    evidence_kind TEXT NOT NULL
                        DEFAULT 'authority_genesis',
                    record_binding_digest TEXT NOT NULL UNIQUE,
                    verification_receipt_digest TEXT NOT NULL UNIQUE,
                    genesis_transition_digest TEXT NOT NULL UNIQUE
                        REFERENCES policy_authority_transition_audits(
                            transition_digest
                        ) ON DELETE RESTRICT,
                    prepared_by TEXT NOT NULL,
                    prepared_at_epoch_ns BIGINT NOT NULL,
                    expires_at_epoch_ns BIGINT NOT NULL,
                    FOREIGN KEY (
                        verification_receipt_digest, evidence_kind,
                        signing_key_id, signature_digest,
                        record_binding_digest
                    ) REFERENCES policy_authority_evidence_verifications (
                        verification_receipt_digest, evidence_kind,
                        signing_key_id, signature_digest,
                        record_binding_digest
                    ) ON DELETE RESTRICT,
                    CHECK (evidence_kind = 'authority_genesis'),
                    CHECK (signature_algorithm = 'Ed25519'),
                    CHECK (policy_sequence > 0),
                    CHECK (rollback_epoch > 0),
                    CHECK (
                        expires_at_epoch_ns > prepared_at_epoch_ns
                    ),
                    CHECK (
                        length(genesis_envelope_json)
                        BETWEEN 2 AND 1048576
                    ),
                    CHECK (
                        length(genesis_payload_json)
                        BETWEEN 2 AND 1048576
                    )
                );

            CREATE TABLE IF NOT EXISTS
                policy_authority_genesis_finalizations (
                    genesis_preparation_digest TEXT PRIMARY KEY
                        REFERENCES policy_authority_genesis_preparations(
                            genesis_preparation_digest
                        ) ON DELETE RESTRICT,
                    policy_id TEXT NOT NULL,
                    policy_sequence BIGINT NOT NULL,
                    rollback_epoch BIGINT NOT NULL,
                    policy_hash TEXT NOT NULL UNIQUE,
                    high_water_digest TEXT NOT NULL UNIQUE,
                    inclusion_receipt_envelope_digest TEXT NOT NULL UNIQUE
                        REFERENCES
                            policy_authority_audit_inclusion_receipts(
                                inclusion_receipt_envelope_digest
                            ) ON DELETE RESTRICT,
                    genesis_transition_digest TEXT NOT NULL UNIQUE,
                    finalization_digest TEXT NOT NULL UNIQUE,
                    finalized_at_epoch_ns BIGINT NOT NULL,
                    UNIQUE (
                        genesis_preparation_digest, policy_id,
                        policy_sequence, rollback_epoch, policy_hash,
                        high_water_digest
                    ),
                    FOREIGN KEY (
                        genesis_transition_digest
                    ) REFERENCES policy_authority_transition_audits(
                        transition_digest
                    ) ON DELETE RESTRICT,
                    CHECK (policy_sequence > 0),
                    CHECK (rollback_epoch > 0),
                    CHECK (finalized_at_epoch_ns >= 0)
                );

            CREATE TABLE IF NOT EXISTS policy_candidate_artifacts (
                artifact_envelope_digest TEXT PRIMARY KEY,
                artifact_payload_digest TEXT NOT NULL UNIQUE,
                candidate_id TEXT NOT NULL UNIQUE,
                scope TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                policy_sequence BIGINT NOT NULL,
                rollback_epoch BIGINT NOT NULL,
                policy_hash TEXT NOT NULL UNIQUE,
                predecessor_policy_sequence BIGINT NOT NULL,
                predecessor_rollback_epoch BIGINT NOT NULL,
                predecessor_policy_hash TEXT NOT NULL,
                compiler_digest TEXT NOT NULL,
                compiler_config_digest TEXT NOT NULL,
                policy_schema_digest TEXT NOT NULL,
                semantic_model_digest TEXT NOT NULL,
                evaluator_abi_digest TEXT NOT NULL,
                policy_bundle_digest TEXT NOT NULL UNIQUE,
                runtime_digest TEXT NOT NULL,
                artifact_envelope_json TEXT NOT NULL,
                artifact_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'candidate_artifact',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                verified_at_epoch_ns BIGINT NOT NULL,
                staged_by TEXT NOT NULL,
                staged_at_epoch_ns BIGINT NOT NULL,
                created_transition_digest TEXT NOT NULL UNIQUE
                    REFERENCES policy_authority_transition_audits(transition_digest)
                    ON DELETE RESTRICT,
                UNIQUE (
                    artifact_envelope_digest, artifact_payload_digest,
                    policy_id, policy_sequence, rollback_epoch, policy_hash,
                    predecessor_policy_sequence, predecessor_rollback_epoch,
                    predecessor_policy_hash, compiler_digest,
                    compiler_config_digest, policy_schema_digest,
                    semantic_model_digest, evaluator_abi_digest,
                    policy_bundle_digest, runtime_digest
                ),
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) REFERENCES policy_authority_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (scope = 'active'),
                CHECK (evidence_kind = 'candidate_artifact'),
                CHECK (policy_sequence > predecessor_policy_sequence),
                CHECK (predecessor_policy_sequence > 0),
                CHECK (rollback_epoch >= predecessor_rollback_epoch),
                CHECK (predecessor_rollback_epoch > 0),
                CHECK (policy_hash <> predecessor_policy_hash),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (verified_at_epoch_ns >= 0),
                CHECK (staged_at_epoch_ns >= verified_at_epoch_ns),
                CHECK (length(candidate_id) BETWEEN 1 AND 256),
                CHECK (length(policy_id) BETWEEN 1 AND 256),
                CHECK (length(staged_by) BETWEEN 1 AND 1024),
                CHECK (length(signing_key_id) BETWEEN 1 AND 1024),
                CHECK (length(signature) BETWEEN 1 AND 4096),
                CHECK (length(artifact_envelope_json) BETWEEN 2 AND 1048576),
                CHECK (length(artifact_payload_json) BETWEEN 2 AND 8388608),
                CHECK (
                    length(artifact_envelope_digest) = 71
                    AND substr(artifact_envelope_digest, 1, 7) = 'sha256:'
                    AND lower(artifact_envelope_digest) = artifact_envelope_digest
                ),
                CHECK (
                    length(artifact_payload_digest) = 71
                    AND substr(artifact_payload_digest, 1, 7) = 'sha256:'
                    AND lower(artifact_payload_digest) = artifact_payload_digest
                ),
                CHECK (
                    length(policy_hash) = 71
                    AND substr(policy_hash, 1, 7) = 'sha256:'
                    AND lower(policy_hash) = policy_hash
                ),
                CHECK (
                    length(predecessor_policy_hash) = 71
                    AND substr(predecessor_policy_hash, 1, 7) = 'sha256:'
                    AND lower(predecessor_policy_hash) = predecessor_policy_hash
                ),
                CHECK (
                    length(compiler_digest) = 71
                    AND substr(compiler_digest, 1, 7) = 'sha256:'
                    AND lower(compiler_digest) = compiler_digest
                ),
                CHECK (
                    length(compiler_config_digest) = 71
                    AND substr(compiler_config_digest, 1, 7) = 'sha256:'
                    AND lower(compiler_config_digest) = compiler_config_digest
                ),
                CHECK (
                    length(policy_schema_digest) = 71
                    AND substr(policy_schema_digest, 1, 7) = 'sha256:'
                    AND lower(policy_schema_digest) = policy_schema_digest
                ),
                CHECK (
                    length(semantic_model_digest) = 71
                    AND substr(semantic_model_digest, 1, 7) = 'sha256:'
                    AND lower(semantic_model_digest) = semantic_model_digest
                ),
                CHECK (
                    length(evaluator_abi_digest) = 71
                    AND substr(evaluator_abi_digest, 1, 7) = 'sha256:'
                    AND lower(evaluator_abi_digest) = evaluator_abi_digest
                ),
                CHECK (
                    length(policy_bundle_digest) = 71
                    AND substr(policy_bundle_digest, 1, 7) = 'sha256:'
                    AND lower(policy_bundle_digest) = policy_bundle_digest
                ),
                CHECK (
                    length(runtime_digest) = 71
                    AND substr(runtime_digest, 1, 7) = 'sha256:'
                    AND lower(runtime_digest) = runtime_digest
                ),
                CHECK (
                    length(signature_digest) = 71
                    AND substr(signature_digest, 1, 7) = 'sha256:'
                    AND lower(signature_digest) = signature_digest
                )
            );

            CREATE INDEX IF NOT EXISTS policy_candidate_artifacts_predecessor_v2
                ON policy_candidate_artifacts (
                    scope, predecessor_policy_hash, policy_sequence
                );

            CREATE TABLE IF NOT EXISTS policy_canaries (
                canary_id TEXT PRIMARY KEY,
                artifact_envelope_digest TEXT NOT NULL,
                artifact_payload_digest TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                candidate_policy_sequence BIGINT NOT NULL,
                candidate_rollback_epoch BIGINT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                predecessor_policy_sequence BIGINT NOT NULL,
                predecessor_rollback_epoch BIGINT NOT NULL,
                predecessor_policy_hash TEXT NOT NULL,
                compiler_digest TEXT NOT NULL,
                compiler_config_digest TEXT NOT NULL,
                policy_schema_digest TEXT NOT NULL,
                semantic_model_digest TEXT NOT NULL,
                evaluator_abi_digest TEXT NOT NULL,
                policy_bundle_digest TEXT NOT NULL,
                runtime_digest TEXT NOT NULL,
                thresholds_digest TEXT NOT NULL,
                expected_instance_count BIGINT NOT NULL,
                minimum_evaluation_count BIGINT NOT NULL,
                created_by TEXT NOT NULL,
                created_at_epoch_ns BIGINT NOT NULL,
                UNIQUE (
                    canary_id, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash
                ),
                UNIQUE (
                    canary_id, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    compiler_digest, compiler_config_digest,
                    policy_schema_digest, semantic_model_digest,
                    evaluator_abi_digest, policy_bundle_digest,
                    runtime_digest
                ),
                FOREIGN KEY (
                    artifact_envelope_digest, artifact_payload_digest,
                    policy_id, candidate_policy_sequence,
                    candidate_rollback_epoch, candidate_policy_hash,
                    predecessor_policy_sequence, predecessor_rollback_epoch,
                    predecessor_policy_hash, compiler_digest,
                    compiler_config_digest, policy_schema_digest,
                    semantic_model_digest, evaluator_abi_digest,
                    policy_bundle_digest, runtime_digest
                ) REFERENCES policy_candidate_artifacts (
                    artifact_envelope_digest, artifact_payload_digest,
                    policy_id, policy_sequence, rollback_epoch, policy_hash,
                    predecessor_policy_sequence, predecessor_rollback_epoch,
                    predecessor_policy_hash, compiler_digest,
                    compiler_config_digest, policy_schema_digest,
                    semantic_model_digest, evaluator_abi_digest,
                    policy_bundle_digest, runtime_digest
                ) ON DELETE RESTRICT,
                CHECK (expected_instance_count > 0),
                CHECK (minimum_evaluation_count > 0),
                CHECK (created_at_epoch_ns >= 0),
                CHECK (length(canary_id) BETWEEN 1 AND 256),
                CHECK (length(created_by) BETWEEN 1 AND 1024),
                CHECK (
                    length(thresholds_digest) = 71
                    AND substr(thresholds_digest, 1, 7) = 'sha256:'
                    AND lower(thresholds_digest) = thresholds_digest
                )
            );

            CREATE TABLE IF NOT EXISTS policy_canary_assignments (
                assignment_envelope_digest TEXT PRIMARY KEY,
                assignment_payload_digest TEXT NOT NULL UNIQUE,
                canary_id TEXT NOT NULL UNIQUE,
                artifact_envelope_digest TEXT NOT NULL,
                artifact_payload_digest TEXT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                compiler_digest TEXT NOT NULL,
                compiler_config_digest TEXT NOT NULL,
                policy_schema_digest TEXT NOT NULL,
                semantic_model_digest TEXT NOT NULL,
                evaluator_abi_digest TEXT NOT NULL,
                policy_bundle_digest TEXT NOT NULL,
                runtime_digest TEXT NOT NULL,
                assignment_id TEXT NOT NULL UNIQUE,
                assignment_revision BIGINT NOT NULL,
                generation_epoch BIGINT NOT NULL,
                minimum_generation_tombstone_epoch BIGINT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_list_json TEXT NOT NULL,
                member_list_digest TEXT NOT NULL,
                attestation_set_json TEXT NOT NULL,
                attestation_set_digest TEXT NOT NULL UNIQUE,
                expected_snapshots_json TEXT NOT NULL,
                expected_snapshots_digest TEXT NOT NULL,
                response_obligations_json TEXT NOT NULL,
                response_obligations_json_digest TEXT NOT NULL,
                response_obligations_digest TEXT NOT NULL,
                observation_window_json TEXT NOT NULL,
                observation_window_digest TEXT NOT NULL,
                readiness_thresholds_json TEXT NOT NULL,
                readiness_thresholds_digest TEXT NOT NULL,
                assignment_envelope_json TEXT NOT NULL,
                assignment_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'canary_assignment',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                created_transition_digest TEXT NOT NULL UNIQUE
                    REFERENCES policy_authority_transition_audits(transition_digest)
                    ON DELETE RESTRICT,
                UNIQUE (
                    assignment_envelope_digest, assignment_payload_digest
                ),
                UNIQUE (
                    canary_id, assignment_envelope_digest,
                    assignment_payload_digest
                ),
                UNIQUE (
                    canary_id, assignment_envelope_digest,
                    assignment_payload_digest, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    compiler_digest, compiler_config_digest,
                    policy_schema_digest, semantic_model_digest,
                    evaluator_abi_digest, policy_bundle_digest,
                    runtime_digest
                ),
                UNIQUE (
                    canary_id, assignment_envelope_digest,
                    assignment_payload_digest, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    compiler_digest, compiler_config_digest,
                    policy_schema_digest, semantic_model_digest,
                    evaluator_abi_digest, policy_bundle_digest,
                    runtime_digest, assignment_id, assignment_revision,
                    generation_epoch, minimum_generation_tombstone_epoch,
                    fleet_id,
                    membership_revision, membership_root_digest,
                    member_list_digest, attestation_set_digest,
                    expected_snapshots_digest,
                    response_obligations_json_digest,
                    response_obligations_digest, observation_window_digest,
                    readiness_thresholds_digest
                ),
                FOREIGN KEY (
                    canary_id, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    compiler_digest, compiler_config_digest,
                    policy_schema_digest, semantic_model_digest,
                    evaluator_abi_digest, policy_bundle_digest,
                    runtime_digest
                ) REFERENCES policy_canaries (
                    canary_id, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    compiler_digest, compiler_config_digest,
                    policy_schema_digest, semantic_model_digest,
                    evaluator_abi_digest, policy_bundle_digest,
                    runtime_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) REFERENCES policy_authority_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (evidence_kind = 'canary_assignment'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (assignment_revision > 0),
                CHECK (generation_epoch > 0),
                CHECK (minimum_generation_tombstone_epoch > 0),
                CHECK (membership_revision > 0),
                CHECK (issued_at_epoch_ns >= 0),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (length(member_list_json) BETWEEN 2 AND 4194304),
                CHECK (length(attestation_set_json) BETWEEN 2 AND 4194304),
                CHECK (length(expected_snapshots_json) BETWEEN 2 AND 1048576),
                CHECK (length(response_obligations_json) BETWEEN 2 AND 1048576),
                CHECK (length(observation_window_json) BETWEEN 2 AND 1048576),
                CHECK (length(readiness_thresholds_json) BETWEEN 2 AND 1048576),
                CHECK (length(assignment_envelope_json) BETWEEN 2 AND 1048576),
                CHECK (length(assignment_payload_json) BETWEEN 2 AND 1048576),
                CHECK (length(signing_key_id) BETWEEN 1 AND 1024),
                CHECK (length(signature) BETWEEN 1 AND 4096),
                CHECK (
                    length(assignment_envelope_digest) = 71
                    AND substr(assignment_envelope_digest, 1, 7) = 'sha256:'
                    AND lower(assignment_envelope_digest) =
                        assignment_envelope_digest
                ),
                CHECK (
                    length(assignment_payload_digest) = 71
                    AND substr(assignment_payload_digest, 1, 7) = 'sha256:'
                    AND lower(assignment_payload_digest) =
                        assignment_payload_digest
                ),
                CHECK (
                    length(fleet_id) = 71
                    AND substr(fleet_id, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(membership_root_digest) = 71
                    AND substr(membership_root_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(member_list_digest) = 71
                    AND substr(member_list_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(attestation_set_digest) = 71
                    AND substr(attestation_set_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(expected_snapshots_digest) = 71
                    AND substr(expected_snapshots_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(response_obligations_json_digest) = 71
                    AND substr(
                        response_obligations_json_digest, 1, 7
                    ) = 'sha256:'
                ),
                CHECK (
                    length(response_obligations_digest) = 71
                    AND substr(response_obligations_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(observation_window_digest) = 71
                    AND substr(observation_window_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(readiness_thresholds_digest) = 71
                    AND substr(readiness_thresholds_digest, 1, 7) = 'sha256:'
                )
            );

            CREATE TABLE IF NOT EXISTS policy_runtime_attestations (
                attestation_receipt_envelope_digest TEXT PRIMARY KEY,
                attestation_receipt_payload_digest TEXT NOT NULL UNIQUE,
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                canary_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                member_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                workload_spiffe_id TEXT NOT NULL,
                tee_platform TEXT NOT NULL,
                tee_evidence_digest TEXT NOT NULL,
                tee_measurement_digest TEXT NOT NULL,
                attestation_key_id TEXT NOT NULL,
                attestation_key_spki_digest TEXT NOT NULL,
                attestation_receipt_envelope_json TEXT NOT NULL,
                attestation_receipt_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'runtime_attestation',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                UNIQUE (
                    attestation_receipt_envelope_digest,
                    attestation_receipt_payload_digest
                ),
                UNIQUE (
                    assignment_envelope_digest, member_ordinal,
                    instance_id, boot_id, attestation_key_spki_digest
                ),
                UNIQUE (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    fleet_id, membership_revision, membership_root_digest,
                    member_id, instance_id, boot_id,
                    tee_measurement_digest,
                    attestation_receipt_envelope_digest
                ),
                FOREIGN KEY (
                    assignment_envelope_digest, assignment_payload_digest
                ) REFERENCES policy_canary_assignments (
                    assignment_envelope_digest, assignment_payload_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) REFERENCES policy_authority_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (evidence_kind = 'runtime_attestation'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (
                    tee_platform IN (
                        'aws-nitro-enclave', 'amd-sev-snp', 'intel-tdx'
                    )
                ),
                CHECK (
                    length(attestation_receipt_envelope_json)
                    BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(attestation_receipt_payload_json)
                    BETWEEN 2 AND 1048576
                )
            );

            CREATE TABLE IF NOT EXISTS policy_canary_assignment_members (
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                canary_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                member_leaf_digest TEXT NOT NULL,
                member_canonical_json TEXT NOT NULL,
                member_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                workload_spiffe_id TEXT NOT NULL,
                tee_platform TEXT NOT NULL,
                tee_measurement_digest TEXT NOT NULL,
                attestation_receipt_envelope_digest TEXT NOT NULL,
                attestation_receipt_payload_digest TEXT NOT NULL,
                assigned_at_epoch_ns BIGINT NOT NULL,
                PRIMARY KEY (assignment_envelope_digest, member_ordinal),
                UNIQUE (assignment_envelope_digest, member_id),
                UNIQUE (assignment_envelope_digest, instance_id),
                UNIQUE (assignment_envelope_digest, workload_spiffe_id),
                UNIQUE (
                    assignment_envelope_digest, instance_id, boot_id
                ),
                UNIQUE (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    fleet_id, membership_revision, membership_root_digest,
                    member_id, instance_id, boot_id,
                    tee_measurement_digest,
                    attestation_receipt_envelope_digest
                ),
                FOREIGN KEY (
                    assignment_envelope_digest, assignment_payload_digest
                ) REFERENCES policy_canary_assignments (
                    assignment_envelope_digest, assignment_payload_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    attestation_receipt_envelope_digest,
                    attestation_receipt_payload_digest
                ) REFERENCES policy_runtime_attestations (
                    attestation_receipt_envelope_digest,
                    attestation_receipt_payload_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    fleet_id, membership_revision, membership_root_digest,
                    member_id, instance_id, boot_id,
                    tee_measurement_digest,
                    attestation_receipt_envelope_digest
                ) REFERENCES policy_runtime_attestations (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    fleet_id, membership_revision, membership_root_digest,
                    member_id, instance_id, boot_id,
                    tee_measurement_digest,
                    attestation_receipt_envelope_digest
                ) ON DELETE RESTRICT,
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (assigned_at_epoch_ns >= 0),
                CHECK (length(member_canonical_json) BETWEEN 2 AND 1048576)
            );

            CREATE TABLE IF NOT EXISTS policy_runtime_role_keys (
                assignment_envelope_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                canary_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                role TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                public_key_base64url TEXT NOT NULL,
                public_key_digest TEXT NOT NULL,
                attestation_receipt_envelope_digest TEXT NOT NULL,
                tee_measurement_digest TEXT NOT NULL,
                not_before_epoch_ns BIGINT NOT NULL,
                not_after_epoch_ns BIGINT NOT NULL,
                authorization_digest TEXT NOT NULL UNIQUE,
                PRIMARY KEY (
                    assignment_envelope_digest, member_ordinal, role,
                    public_key_digest
                ),
                UNIQUE (
                    assignment_envelope_digest, member_ordinal, role
                ),
                UNIQUE (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    fleet_id, membership_revision, membership_root_digest,
                    member_id, instance_id, boot_id, role, public_key_digest,
                    attestation_receipt_envelope_digest,
                    tee_measurement_digest, authorization_digest
                ),
                FOREIGN KEY (
                    assignment_envelope_digest, member_ordinal
                ) REFERENCES policy_canary_assignment_members (
                    assignment_envelope_digest, member_ordinal
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    fleet_id, membership_revision, membership_root_digest,
                    member_id, instance_id, boot_id,
                    tee_measurement_digest,
                    attestation_receipt_envelope_digest
                ) REFERENCES policy_canary_assignment_members (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    fleet_id, membership_revision, membership_root_digest,
                    member_id, instance_id, boot_id,
                    tee_measurement_digest,
                    attestation_receipt_envelope_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    attestation_receipt_envelope_digest
                ) REFERENCES policy_runtime_attestations (
                    attestation_receipt_envelope_digest
                ) ON DELETE RESTRICT,
                CHECK (
                    role IN (
                        'attestation', 'custody', 'export', 'ingress',
                        'active-decision', 'shadow'
                    )
                ),
                CHECK (signing_key_id = public_key_digest),
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (not_before_epoch_ns >= 0),
                CHECK (not_after_epoch_ns > not_before_epoch_ns),
                CHECK (length(public_key_base64url) = 43)
            );

            CREATE INDEX IF NOT EXISTS policy_runtime_role_keys_active_set
                ON policy_runtime_role_keys (
                    assignment_envelope_digest, member_ordinal, role,
                    fleet_id, member_id, instance_id, boot_id,
                    public_key_digest, authorization_digest,
                    not_before_epoch_ns, not_after_epoch_ns
                );

            CREATE TABLE IF NOT EXISTS policy_runtime_role_key_revocations (
                revocation_envelope_digest TEXT PRIMARY KEY,
                revocation_payload_digest TEXT NOT NULL UNIQUE,
                assignment_envelope_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                canary_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                role TEXT NOT NULL,
                public_key_digest TEXT NOT NULL,
                attestation_receipt_envelope_digest TEXT NOT NULL,
                tee_measurement_digest TEXT NOT NULL,
                authorization_digest TEXT NOT NULL,
                revocation_sequence BIGINT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                revoked_by TEXT NOT NULL,
                revoked_at_epoch_ns BIGINT NOT NULL,
                revocation_envelope_json TEXT NOT NULL,
                revocation_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'runtime_role_revocation',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                created_transition_digest TEXT NOT NULL UNIQUE
                    REFERENCES policy_authority_transition_audits(
                        transition_digest
                    ) ON DELETE RESTRICT,
                UNIQUE (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    fleet_id, membership_revision, membership_root_digest,
                    member_id, instance_id, boot_id, role, public_key_digest,
                    attestation_receipt_envelope_digest,
                    tee_measurement_digest, authorization_digest
                ),
                FOREIGN KEY (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    fleet_id, membership_revision, membership_root_digest,
                    member_id, instance_id, boot_id, role, public_key_digest,
                    attestation_receipt_envelope_digest,
                    tee_measurement_digest, authorization_digest
                ) REFERENCES policy_runtime_role_keys (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    fleet_id, membership_revision, membership_root_digest,
                    member_id, instance_id, boot_id, role, public_key_digest,
                    attestation_receipt_envelope_digest,
                    tee_measurement_digest, authorization_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) REFERENCES policy_authority_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (evidence_kind = 'runtime_role_revocation'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (
                    role IN (
                        'attestation', 'custody', 'export', 'ingress',
                        'active-decision', 'shadow'
                    )
                ),
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (revocation_sequence > 0),
                CHECK (revoked_at_epoch_ns >= 0),
                CHECK (length(revoked_by) BETWEEN 1 AND 1024)
            );

            CREATE TABLE IF NOT EXISTS policy_runtime_evidence_verifications (
                verification_receipt_digest TEXT PRIMARY KEY,
                evidence_kind TEXT NOT NULL,
                required_role TEXT NOT NULL,
                assignment_envelope_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                canary_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                public_key_digest TEXT NOT NULL,
                signature_domain TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                record_binding_digest TEXT NOT NULL UNIQUE,
                envelope_digest TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                signature_message_digest TEXT NOT NULL UNIQUE,
                role_authorization_digest TEXT NOT NULL,
                attestation_receipt_envelope_digest TEXT NOT NULL,
                revocation_sequence BIGINT NOT NULL,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                verified_at_epoch_ns BIGINT NOT NULL,
                UNIQUE (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ),
                FOREIGN KEY (
                    assignment_envelope_digest, member_ordinal,
                    required_role, public_key_digest
                ) REFERENCES policy_runtime_role_keys (
                    assignment_envelope_digest, member_ordinal, role,
                    public_key_digest
                ) ON DELETE RESTRICT,
                CHECK (
                    required_role IN (
                        'attestation', 'custody', 'export', 'ingress',
                        'active-decision', 'shadow'
                    )
                ),
                CHECK (signing_key_id = public_key_digest),
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (revocation_sequence >= 0),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (
                    verified_at_epoch_ns >= issued_at_epoch_ns
                    AND verified_at_epoch_ns < expires_at_epoch_ns
                )
            );

            CREATE TABLE IF NOT EXISTS policy_compiler_authority_analyses (
                analysis_envelope_digest TEXT PRIMARY KEY,
                analysis_payload_digest TEXT NOT NULL UNIQUE,
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                assignment_revision BIGINT NOT NULL,
                canary_id TEXT NOT NULL,
                artifact_envelope_digest TEXT NOT NULL,
                artifact_payload_digest TEXT NOT NULL,
                compiler_digest TEXT NOT NULL,
                compiler_config_digest TEXT NOT NULL,
                policy_schema_digest TEXT NOT NULL,
                semantic_model_digest TEXT NOT NULL,
                route_authority_root_digest TEXT NOT NULL,
                operation_authority_root_digest TEXT NOT NULL,
                response_obligations_digest TEXT NOT NULL,
                analysis_mode TEXT NOT NULL,
                approval_mode TEXT NOT NULL,
                required_approval_quorum BIGINT NOT NULL,
                expansion_cells_json TEXT NOT NULL,
                expansion_cells_digest TEXT NOT NULL,
                pilot_restrictions_json TEXT NOT NULL,
                pilot_restrictions_digest TEXT NOT NULL,
                analysis_envelope_json TEXT NOT NULL,
                analysis_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'compiler_analysis',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                UNIQUE (
                    analysis_envelope_digest, analysis_payload_digest
                ),
                UNIQUE (
                    assignment_envelope_digest, analysis_payload_digest
                ),
                FOREIGN KEY (
                    assignment_envelope_digest, assignment_payload_digest
                ) REFERENCES policy_canary_assignments (
                    assignment_envelope_digest, assignment_payload_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) REFERENCES policy_authority_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (evidence_kind = 'compiler_analysis'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (assignment_revision > 0),
                CHECK (
                    (analysis_mode = 'no-expansion'
                        AND approval_mode = 'none'
                        AND required_approval_quorum = 1)
                    OR
                    (analysis_mode = 'approved-expansion'
                        AND approval_mode IN (
                            'single-person-hardware-webauthn',
                            'two-person-hardware-webauthn'
                        )
                        AND required_approval_quorum IN (1, 2))
                ),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (length(expansion_cells_json) BETWEEN 2 AND 4194304),
                CHECK (length(pilot_restrictions_json) BETWEEN 2 AND 1048576),
                CHECK (length(analysis_envelope_json) BETWEEN 2 AND 1048576),
                CHECK (length(analysis_payload_json) BETWEEN 2 AND 4194304)
            );

            CREATE TABLE IF NOT EXISTS policy_canary_revisions (
                canary_id TEXT NOT NULL
                    REFERENCES policy_canaries(canary_id) ON DELETE RESTRICT,
                revision BIGINT NOT NULL,
                status TEXT NOT NULL,
                previous_revision BIGINT,
                previous_status TEXT,
                previous_state_digest TEXT,
                assignment_envelope_digest TEXT,
                assignment_payload_digest TEXT,
                sealed_checkpoint_root_digest TEXT,
                sealed_instance_set_digest TEXT,
                readiness_envelope_digest TEXT,
                readiness_payload_digest TEXT,
                state_envelope_json TEXT NOT NULL,
                state_payload_json TEXT NOT NULL,
                state_digest TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'canary_state',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                created_at_epoch_ns BIGINT NOT NULL,
                observation_started_at_epoch_ns BIGINT,
                sealed_at_epoch_ns BIGINT,
                terminal_from_status TEXT,
                terminal_at_epoch_ns BIGINT,
                transition_digest TEXT NOT NULL UNIQUE,
                transition_entity_kind TEXT NOT NULL DEFAULT 'canary',
                transition_event_type TEXT NOT NULL,
                PRIMARY KEY (canary_id, revision),
                UNIQUE (canary_id, revision, state_digest),
                UNIQUE (canary_id, revision, state_digest, status),
                FOREIGN KEY (
                    canary_id, previous_revision, previous_state_digest,
                    previous_status
                ) REFERENCES policy_canary_revisions (
                    canary_id, revision, state_digest, status
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, assignment_envelope_digest,
                    assignment_payload_digest
                ) REFERENCES policy_canary_assignments (
                    canary_id, assignment_envelope_digest,
                    assignment_payload_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    transition_digest, transition_entity_kind, canary_id,
                    revision, state_digest, previous_state_digest,
                    transition_event_type
                ) REFERENCES policy_authority_transition_audits (
                    transition_digest, entity_kind, entity_id,
                    entity_revision, state_digest, previous_state_digest,
                    event_type
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) REFERENCES policy_authority_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (
                    status IN (
                        'staged', 'distributing', 'observing', 'sealing',
                        'ready', 'activating', 'active', 'verifying',
                        'indeterminate', 'completed', 'failed', 'cancelled',
                        'expired', 'superseded'
                    )
                ),
                CHECK (revision > 0),
                CHECK (
                    (
                        revision = 1
                        AND status = 'staged'
                        AND previous_revision IS NULL
                        AND previous_status IS NULL
                        AND previous_state_digest IS NULL
                    )
                    OR (
                        revision > 1
                        AND previous_revision = revision - 1
                        AND previous_status IS NOT NULL
                        AND previous_state_digest IS NOT NULL
                    )
                ),
                CHECK (evidence_kind = 'canary_state'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (
                    revision = 1
                    OR (previous_status = 'staged' AND status IN (
                        'distributing', 'failed', 'cancelled', 'expired',
                        'superseded'
                    ))
                    OR (previous_status = 'distributing' AND status IN (
                        'observing', 'failed', 'cancelled', 'expired',
                        'superseded'
                    ))
                    OR (previous_status = 'observing' AND status IN (
                        'sealing', 'failed', 'cancelled', 'expired',
                        'superseded'
                    ))
                    OR (previous_status = 'sealing' AND status IN (
                        'ready', 'failed', 'cancelled', 'expired', 'superseded'
                    ))
                    OR (previous_status = 'ready' AND status IN (
                        'activating', 'failed', 'cancelled', 'expired',
                        'superseded'
                    ))
                    OR (previous_status = 'activating' AND status IN (
                        'active', 'indeterminate', 'failed', 'superseded'
                    ))
                    OR (previous_status = 'active' AND status IN (
                        'verifying', 'indeterminate', 'failed', 'superseded'
                    ))
                    OR (previous_status = 'verifying' AND status IN (
                        'completed', 'indeterminate', 'failed', 'superseded'
                    ))
                ),
                CHECK (
                    (
                        assignment_envelope_digest IS NULL
                        AND assignment_payload_digest IS NULL
                    )
                    OR (
                        assignment_envelope_digest IS NOT NULL
                        AND assignment_payload_digest IS NOT NULL
                    )
                ),
                CHECK (
                    status = 'staged'
                    OR (
                        assignment_envelope_digest IS NOT NULL
                        AND assignment_payload_digest IS NOT NULL
                    )
                ),
                CHECK (
                    (
                        sealed_checkpoint_root_digest IS NULL
                        AND sealed_instance_set_digest IS NULL
                        AND readiness_envelope_digest IS NULL
                        AND readiness_payload_digest IS NULL
                        AND sealed_at_epoch_ns IS NULL
                    )
                    OR (
                        sealed_checkpoint_root_digest IS NOT NULL
                        AND sealed_instance_set_digest IS NOT NULL
                        AND readiness_envelope_digest IS NOT NULL
                        AND readiness_payload_digest IS NOT NULL
                        AND sealed_at_epoch_ns IS NOT NULL
                    )
                ),
                CHECK (
                    status NOT IN (
                        'ready', 'activating', 'active', 'verifying',
                        'completed'
                    )
                    OR readiness_payload_digest IS NOT NULL
                ),
                CHECK (created_at_epoch_ns >= 0),
                CHECK (
                    observation_started_at_epoch_ns IS NULL
                    OR observation_started_at_epoch_ns >= created_at_epoch_ns
                ),
                CHECK (
                    sealed_at_epoch_ns IS NULL
                    OR (
                        observation_started_at_epoch_ns IS NOT NULL
                        AND sealed_at_epoch_ns >= observation_started_at_epoch_ns
                    )
                ),
                CHECK (
                    (
                        status IN (
                            'completed', 'indeterminate', 'failed',
                            'cancelled', 'expired', 'superseded'
                        )
                        AND terminal_from_status = previous_status
                        AND terminal_at_epoch_ns IS NOT NULL
                        AND terminal_at_epoch_ns >= created_at_epoch_ns
                    )
                    OR (
                        status NOT IN (
                            'completed', 'indeterminate', 'failed',
                            'cancelled', 'expired', 'superseded'
                        )
                        AND terminal_from_status IS NULL
                        AND terminal_at_epoch_ns IS NULL
                    )
                ),
                CHECK (transition_entity_kind = 'canary'),
                CHECK (length(state_envelope_json) BETWEEN 2 AND 1048576),
                CHECK (length(state_payload_json) BETWEEN 2 AND 1048576),
                CHECK (length(signing_key_id) BETWEEN 1 AND 1024),
                CHECK (length(signature) BETWEEN 1 AND 4096),
                CHECK (
                    length(state_digest) = 71
                    AND substr(state_digest, 1, 7) = 'sha256:'
                    AND lower(state_digest) = state_digest
                )
            );

            CREATE INDEX IF NOT EXISTS policy_canary_revisions_predecessor
                ON policy_canary_revisions (
                    canary_id, previous_revision, previous_state_digest
                );

            CREATE TABLE IF NOT EXISTS policy_canary_heads (
                canary_id TEXT PRIMARY KEY
                    REFERENCES policy_canaries(canary_id) ON DELETE RESTRICT,
                head_revision BIGINT NOT NULL,
                head_state_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                updated_at_epoch_ns BIGINT NOT NULL,
                FOREIGN KEY (
                    canary_id, head_revision, head_state_digest, status
                ) REFERENCES policy_canary_revisions (
                    canary_id, revision, state_digest, status
                ) ON DELETE RESTRICT,
                CHECK (head_revision > 0),
                CHECK (updated_at_epoch_ns >= 0)
            );

            CREATE TABLE IF NOT EXISTS policy_canary_instances (
                canary_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                member_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                artifact_envelope_digest TEXT NOT NULL,
                artifact_payload_digest TEXT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                compiler_digest TEXT NOT NULL,
                compiler_config_digest TEXT NOT NULL,
                policy_schema_digest TEXT NOT NULL,
                semantic_model_digest TEXT NOT NULL,
                evaluator_abi_digest TEXT NOT NULL,
                policy_bundle_digest TEXT NOT NULL,
                runtime_digest TEXT NOT NULL,
                workload_spiffe_id TEXT NOT NULL,
                tee_platform TEXT NOT NULL,
                attestation_evidence_digest TEXT NOT NULL,
                attestation_verifier_receipt_digest TEXT NOT NULL,
                boot_public_key_digest TEXT NOT NULL,
                boot_signing_key_id TEXT NOT NULL,
                assigned_at_epoch_ns BIGINT NOT NULL,
                PRIMARY KEY (canary_id, instance_id, boot_id),
                UNIQUE (canary_id, member_ordinal),
                UNIQUE (canary_id, member_id),
                UNIQUE (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ),
                UNIQUE (
                    canary_id, instance_id, boot_id,
                    assignment_envelope_digest, assignment_payload_digest,
                    artifact_envelope_digest, artifact_payload_digest,
                    candidate_policy_hash, runtime_digest,
                    boot_public_key_digest, boot_signing_key_id
                ),
                UNIQUE (
                    canary_id, instance_id, boot_id,
                    assignment_envelope_digest, assignment_payload_digest,
                    artifact_envelope_digest, artifact_payload_digest,
                    candidate_policy_hash, compiler_digest,
                    compiler_config_digest, policy_schema_digest,
                    semantic_model_digest, evaluator_abi_digest,
                    policy_bundle_digest, runtime_digest,
                    boot_public_key_digest, boot_signing_key_id
                ),
                FOREIGN KEY (
                    canary_id, assignment_envelope_digest,
                    assignment_payload_digest, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    compiler_digest, compiler_config_digest,
                    policy_schema_digest, semantic_model_digest,
                    evaluator_abi_digest, policy_bundle_digest,
                    runtime_digest
                ) REFERENCES policy_canary_assignments (
                    canary_id, assignment_envelope_digest,
                    assignment_payload_digest, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    compiler_digest, compiler_config_digest,
                    policy_schema_digest, semantic_model_digest,
                    evaluator_abi_digest, policy_bundle_digest,
                    runtime_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    assignment_envelope_digest, member_ordinal
                ) REFERENCES policy_canary_assignment_members (
                    assignment_envelope_digest, member_ordinal
                ) ON DELETE RESTRICT,
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (assigned_at_epoch_ns >= 0),
                CHECK (length(instance_id) BETWEEN 1 AND 256),
                CHECK (length(boot_id) BETWEEN 1 AND 256),
                CHECK (length(workload_spiffe_id) BETWEEN 1 AND 2048),
                CHECK (length(tee_platform) BETWEEN 1 AND 128),
                CHECK (length(boot_signing_key_id) BETWEEN 1 AND 1024)
            );

            CREATE TABLE IF NOT EXISTS policy_canary_load_receipts (
                load_receipt_envelope_digest TEXT PRIMARY KEY,
                load_receipt_payload_digest TEXT NOT NULL UNIQUE,
                canary_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                member_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                artifact_envelope_digest TEXT NOT NULL,
                artifact_payload_digest TEXT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                compiler_digest TEXT NOT NULL,
                compiler_config_digest TEXT NOT NULL,
                policy_schema_digest TEXT NOT NULL,
                semantic_model_digest TEXT NOT NULL,
                evaluator_abi_digest TEXT NOT NULL,
                policy_bundle_digest TEXT NOT NULL,
                runtime_digest TEXT NOT NULL,
                attestation_evidence_digest TEXT NOT NULL,
                attestation_verifier_receipt_digest TEXT NOT NULL,
                boot_public_key_digest TEXT NOT NULL,
                boot_signing_key_id TEXT NOT NULL,
                load_receipt_envelope_json TEXT NOT NULL,
                load_receipt_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'load_receipt',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                loaded_at_epoch_ns BIGINT NOT NULL,
                created_transition_digest TEXT NOT NULL UNIQUE
                    REFERENCES policy_authority_transition_audits(transition_digest)
                    ON DELETE RESTRICT,
                UNIQUE (canary_id, instance_id, boot_id),
                UNIQUE (
                    load_receipt_envelope_digest,
                    load_receipt_payload_digest
                ),
                UNIQUE (
                    canary_id, instance_id, boot_id,
                    load_receipt_envelope_digest,
                    load_receipt_payload_digest
                ),
                UNIQUE (
                    canary_id, instance_id, boot_id,
                    load_receipt_envelope_digest,
                    load_receipt_payload_digest,
                    assignment_envelope_digest, assignment_payload_digest,
                    artifact_envelope_digest, artifact_payload_digest,
                    candidate_policy_hash, compiler_digest,
                    compiler_config_digest, policy_schema_digest,
                    semantic_model_digest, evaluator_abi_digest,
                    policy_bundle_digest, runtime_digest,
                    boot_public_key_digest, boot_signing_key_id
                ),
                FOREIGN KEY (
                    canary_id, instance_id, boot_id,
                    assignment_envelope_digest, assignment_payload_digest,
                    artifact_envelope_digest, artifact_payload_digest,
                    candidate_policy_hash, compiler_digest,
                    compiler_config_digest, policy_schema_digest,
                    semantic_model_digest, evaluator_abi_digest,
                    policy_bundle_digest, runtime_digest,
                    boot_public_key_digest, boot_signing_key_id
                ) REFERENCES policy_canary_instances (
                    canary_id, instance_id, boot_id,
                    assignment_envelope_digest, assignment_payload_digest,
                    artifact_envelope_digest, artifact_payload_digest,
                    candidate_policy_hash, compiler_digest,
                    compiler_config_digest, policy_schema_digest,
                    semantic_model_digest, evaluator_abi_digest,
                    policy_bundle_digest, runtime_digest,
                    boot_public_key_digest, boot_signing_key_id
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) REFERENCES policy_canary_instances (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) REFERENCES policy_runtime_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (evidence_kind = 'load_receipt'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (signing_key_id = boot_signing_key_id),
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (loaded_at_epoch_ns >= 0),
                CHECK (length(load_receipt_envelope_json) BETWEEN 2 AND 1048576),
                CHECK (length(load_receipt_payload_json) BETWEEN 2 AND 1048576),
                CHECK (length(signature) BETWEEN 1 AND 4096),
                CHECK (
                    length(load_receipt_envelope_digest) = 71
                    AND substr(load_receipt_envelope_digest, 1, 7) = 'sha256:'
                    AND lower(load_receipt_envelope_digest) =
                        load_receipt_envelope_digest
                ),
                CHECK (
                    length(load_receipt_payload_digest) = 71
                    AND substr(load_receipt_payload_digest, 1, 7) = 'sha256:'
                    AND lower(load_receipt_payload_digest) =
                        load_receipt_payload_digest
                )
            );

            CREATE TABLE IF NOT EXISTS
                policy_shadow_runtime_attestation_handoffs (
                    runtime_attestation_handoff_digest TEXT PRIMARY KEY,
                    runtime_attestation_handoff_json TEXT NOT NULL UNIQUE,
                    canary_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    boot_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    assignment_envelope_digest TEXT NOT NULL,
                    assignment_payload_digest TEXT NOT NULL,
                    assignment_revision BIGINT NOT NULL,
                    load_receipt_envelope_digest TEXT NOT NULL,
                    load_receipt_payload_digest TEXT NOT NULL,
                    receipt_id TEXT NOT NULL,
                    receipt_revision BIGINT NOT NULL,
                    receipt_envelope_digest TEXT NOT NULL,
                    receipt_payload_digest TEXT NOT NULL,
                    role_authorization_id TEXT NOT NULL,
                    role_authorization_revision BIGINT NOT NULL,
                    role_authorization_envelope_digest TEXT NOT NULL UNIQUE,
                    role_authorization_payload_digest TEXT NOT NULL UNIQUE,
                    role_authorization_envelope_json TEXT NOT NULL,
                    role_authorization_payload_json TEXT NOT NULL,
                    role_authorization_signature_algorithm TEXT NOT NULL,
                    role_authorization_signing_key_id TEXT NOT NULL,
                    role_authorization_signature TEXT NOT NULL,
                    role_authorization_signature_digest TEXT NOT NULL UNIQUE,
                    role_authorization_evidence_kind TEXT NOT NULL DEFAULT
                        'shadow_role_authorization',
                    role_authorization_record_binding_digest TEXT NOT NULL
                        UNIQUE,
                    role_authorization_verification_receipt_digest TEXT NOT NULL
                        UNIQUE,
                    attestation_evidence_id TEXT NOT NULL,
                    attestation_evidence_revision BIGINT NOT NULL,
                    attestation_evidence_type TEXT NOT NULL,
                    attestation_evidence_digest TEXT NOT NULL,
                    attestation_evidence_json TEXT NOT NULL,
                    attestation_chain_digest TEXT NOT NULL UNIQUE,
                    runtime_identity_digest TEXT NOT NULL,
                    runtime_executable_digest TEXT NOT NULL,
                    runtime_release_digest TEXT NOT NULL,
                    runtime_config_digest TEXT NOT NULL,
                    runtime_policy_digest TEXT NOT NULL,
                    attestation_policy_digest TEXT NOT NULL,
                    attestation_trust_checkpoint_digest TEXT NOT NULL,
                    attestation_revocation_generation BIGINT NOT NULL,
                    attestation_revocation_root_digest TEXT NOT NULL,
                    shadow_signing_key_id TEXT NOT NULL,
                    shadow_signing_key_spki_digest TEXT NOT NULL,
                    shadow_role_key_authorization_digest TEXT NOT NULL,
                    tee_measurement_digest TEXT NOT NULL,
                    issued_at_epoch_ns BIGINT NOT NULL,
                    expires_at_epoch_ns BIGINT NOT NULL,
                    created_transition_digest TEXT NOT NULL UNIQUE
                        REFERENCES policy_authority_transition_audits(
                            transition_digest
                    ) ON DELETE RESTRICT,
                    UNIQUE (canary_id, instance_id, boot_id),
                    UNIQUE (
                        canary_id, instance_id, boot_id,
                        attestation_chain_digest, receipt_envelope_digest,
                        role_authorization_envelope_digest,
                        shadow_signing_key_id
                    ),
                    FOREIGN KEY (
                        receipt_envelope_digest, receipt_payload_digest
                    ) REFERENCES policy_runtime_attestations (
                        attestation_receipt_envelope_digest,
                        attestation_receipt_payload_digest
                    ) ON DELETE RESTRICT,
                    FOREIGN KEY (
                        canary_id, instance_id, boot_id,
                        load_receipt_envelope_digest,
                        load_receipt_payload_digest
                    ) REFERENCES policy_canary_load_receipts (
                        canary_id, instance_id, boot_id,
                        load_receipt_envelope_digest,
                        load_receipt_payload_digest
                    ) ON DELETE RESTRICT,
                    FOREIGN KEY (
                        role_authorization_verification_receipt_digest,
                        role_authorization_evidence_kind,
                        role_authorization_signing_key_id,
                        role_authorization_signature_digest,
                        role_authorization_record_binding_digest
                    ) REFERENCES policy_authority_evidence_verifications (
                        verification_receipt_digest, evidence_kind,
                        signing_key_id, signature_digest,
                        record_binding_digest
                    ) ON DELETE RESTRICT,
                    CHECK (
                        role_authorization_evidence_kind =
                            'shadow_role_authorization'
                    ),
                    CHECK (
                        role_authorization_signature_algorithm = 'Ed25519'
                    ),
                    CHECK (
                        shadow_signing_key_id =
                            shadow_signing_key_spki_digest
                    ),
                    CHECK (assignment_revision > 0),
                    CHECK (receipt_revision > 0),
                    CHECK (role_authorization_revision > 0),
                    CHECK (attestation_evidence_revision > 0),
                    CHECK (attestation_revocation_generation > 0),
                    CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                    CHECK (
                        attestation_evidence_type IN (
                            'aws-nitro-enclave', 'amd-sev-snp',
                            'intel-tdx'
                        )
                    ),
                    CHECK (
                        length(runtime_attestation_handoff_json)
                        BETWEEN 2 AND 2097152
                    ),
                    CHECK (
                        length(role_authorization_envelope_json)
                        BETWEEN 2 AND 1048576
                    ),
                    CHECK (
                        length(role_authorization_payload_json)
                        BETWEEN 2 AND 1048576
                    ),
                    CHECK (
                        length(attestation_evidence_json)
                        BETWEEN 2 AND 1048576
                    )
                );

            CREATE TABLE IF NOT EXISTS policy_shadow_generation_publications (
                generation_publication_envelope_digest TEXT PRIMARY KEY,
                generation_publication_payload_digest TEXT NOT NULL UNIQUE,
                request_id TEXT NOT NULL UNIQUE,
                replay_id TEXT NOT NULL UNIQUE,
                management_handoff_id TEXT NOT NULL UNIQUE,
                request_payload_digest TEXT NOT NULL UNIQUE,
                management_handoff_identity_digest TEXT NOT NULL,
                management_request_json TEXT NOT NULL,
                management_actor_id TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                canary_id TEXT NOT NULL,
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                assignment_revision BIGINT NOT NULL,
                generation_epoch BIGINT NOT NULL,
                minimum_generation_tombstone_epoch BIGINT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                member_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                load_receipt_envelope_digest TEXT NOT NULL,
                load_receipt_payload_digest TEXT NOT NULL,
                generation_id_digest TEXT NOT NULL UNIQUE,
                generation_preparation_envelope_digest TEXT NOT NULL UNIQUE,
                publication_revision BIGINT NOT NULL,
                custody_configuration_digest TEXT NOT NULL,
                custody_preparation_receipt_digest TEXT NOT NULL,
                custody_publication_receipt_digest TEXT NOT NULL UNIQUE,
                publication_reconciliation_receipt_digest TEXT NOT NULL,
                custody_high_water_digest TEXT NOT NULL UNIQUE,
                custody_sequence BIGINT NOT NULL,
                authoritative_spool_root_digest TEXT NOT NULL,
                ingress_high_water_digest TEXT NOT NULL UNIQUE,
                ingress_sequence BIGINT NOT NULL,
                ingress_range_start_sequence BIGINT NOT NULL,
                observation_interval_digest TEXT NOT NULL,
                response_obligations_digest TEXT NOT NULL,
                request_commitment_key_epoch BIGINT NOT NULL,
                request_facts_schema_digest TEXT NOT NULL,
                active_policy_hash TEXT NOT NULL,
                active_policy_sequence BIGINT NOT NULL,
                active_rollback_epoch BIGINT NOT NULL,
                active_policy_bundle_digest TEXT NOT NULL,
                active_compiled_snapshot_digest TEXT NOT NULL,
                active_compiled_behavior_digest TEXT NOT NULL,
                active_runtime_snapshot_epoch BIGINT NOT NULL,
                active_policy_trust_generation BIGINT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                candidate_policy_sequence BIGINT NOT NULL,
                candidate_rollback_epoch BIGINT NOT NULL,
                candidate_policy_bundle_digest TEXT NOT NULL,
                candidate_compiled_snapshot_digest TEXT NOT NULL,
                candidate_compiled_behavior_digest TEXT NOT NULL,
                candidate_runtime_snapshot_epoch BIGINT NOT NULL,
                candidate_policy_trust_generation BIGINT NOT NULL,
                runtime_executable_digest TEXT NOT NULL,
                runtime_measurement_digest TEXT NOT NULL,
                runtime_release_digest TEXT NOT NULL,
                image_signatures_digest TEXT NOT NULL,
                generation_trust_manifest_digest TEXT NOT NULL,
                policy_compiler_binary_digest TEXT NOT NULL,
                runtime_config_digest TEXT NOT NULL,
                policy_schema_digest TEXT NOT NULL,
                adapter_schema_digest TEXT NOT NULL,
                policy_semantic_model_digest TEXT NOT NULL,
                policy_plan_schema_digest TEXT NOT NULL,
                runtime_attestation_verifier_executable_digest TEXT NOT NULL,
                publication_handoff_executable_digest TEXT NOT NULL,
                active_policy_signing_key_id TEXT NOT NULL,
                runtime_instance_id TEXT NOT NULL,
                runtime_identity_digest TEXT NOT NULL,
                runtime_policy_digest TEXT NOT NULL,
                attestation_policy_digest TEXT NOT NULL,
                attestation_trust_checkpoint_digest TEXT NOT NULL,
                attestation_revocation_generation BIGINT NOT NULL,
                attestation_revocation_root_digest TEXT NOT NULL,
                runtime_attestation_verifier_signing_key_id TEXT NOT NULL,
                runtime_attestation_verifier_signing_key_spki_digest
                    TEXT NOT NULL,
                publication_signing_key_id TEXT NOT NULL,
                publication_signing_key_spki_digest TEXT NOT NULL,
                publication_replay_store_digest TEXT NOT NULL,
                replay_store_revision BIGINT NOT NULL,
                runtime_attestation_receipt_envelope_digest TEXT NOT NULL,
                runtime_attestation_receipt_payload_digest TEXT NOT NULL,
                runtime_attestation_verification_receipt_digest TEXT NOT NULL,
                runtime_attestation_verification_envelope_digest TEXT NOT NULL
                    UNIQUE,
                rust_attestation_verification_receipt_digest TEXT NOT NULL
                    UNIQUE,
                attestation_role_authorization_digest TEXT NOT NULL,
                runtime_attestation_evidence_json TEXT NOT NULL,
                runtime_attestation_verification_envelope_json TEXT NOT NULL,
                runtime_attestation_verification_payload_json TEXT NOT NULL,
                runtime_attestation_verifier_signature_algorithm TEXT NOT NULL,
                runtime_attestation_verifier_signature TEXT NOT NULL,
                runtime_attestation_verifier_signature_digest TEXT NOT NULL
                    UNIQUE,
                runtime_attestation_verifier_record_binding_digest
                    TEXT NOT NULL UNIQUE,
                runtime_attestation_evidence_kind TEXT NOT NULL DEFAULT
                    'generation_runtime_attestation_verification',
                attestation_evidence_digest TEXT NOT NULL,
                tee_measurement_digest TEXT NOT NULL,
                attestation_chain_digest TEXT NOT NULL UNIQUE,
                attestation_chain_json TEXT NOT NULL,
                attestation_mode TEXT NOT NULL,
                hardware_attested BOOLEAN NOT NULL,
                durable_commit_receipt_digest TEXT NOT NULL UNIQUE,
                generation_evidence_json TEXT NOT NULL,
                generation_publication_envelope_json TEXT NOT NULL,
                generation_publication_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'generation_publication',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                not_before_epoch_ns BIGINT NOT NULL,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                runtime_attestation_trusted_at_epoch_ns BIGINT NOT NULL,
                runtime_attestation_issued_at_epoch_ns BIGINT NOT NULL,
                runtime_attestation_expires_at_epoch_ns BIGINT NOT NULL,
                created_transition_digest TEXT NOT NULL UNIQUE
                    REFERENCES policy_authority_transition_audits(
                        transition_digest
                    ) ON DELETE RESTRICT,
                UNIQUE (canary_id, instance_id, boot_id),
                UNIQUE (
                    assignment_envelope_digest, member_ordinal,
                    publication_revision
                ),
                UNIQUE (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    instance_id, boot_id, generation_id_digest
                ),
                UNIQUE (
                    request_id, request_payload_digest,
                    generation_publication_envelope_digest,
                    generation_publication_payload_digest
                ),
                FOREIGN KEY (
                    canary_id, instance_id, boot_id,
                    load_receipt_envelope_digest,
                    load_receipt_payload_digest
                ) REFERENCES policy_canary_load_receipts (
                    canary_id, instance_id, boot_id,
                    load_receipt_envelope_digest,
                    load_receipt_payload_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    runtime_attestation_receipt_envelope_digest,
                    runtime_attestation_receipt_payload_digest
                ) REFERENCES policy_runtime_attestations (
                    attestation_receipt_envelope_digest,
                    attestation_receipt_payload_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, instance_id, boot_id,
                    attestation_chain_digest,
                    runtime_attestation_receipt_envelope_digest,
                    attestation_role_authorization_digest,
                    signing_key_id
                ) REFERENCES policy_shadow_runtime_attestation_handoffs (
                    canary_id, instance_id, boot_id,
                    attestation_chain_digest, receipt_envelope_digest,
                    role_authorization_envelope_digest,
                    shadow_signing_key_id
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    rust_attestation_verification_receipt_digest,
                    runtime_attestation_evidence_kind,
                    runtime_attestation_verifier_signing_key_id,
                    runtime_attestation_verifier_signature_digest,
                    runtime_attestation_verifier_record_binding_digest
                ) REFERENCES policy_authority_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest,
                    record_binding_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest,
                    record_binding_digest
                ) REFERENCES policy_authority_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest,
                    record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (evidence_kind = 'generation_publication'),
                CHECK (
                    runtime_attestation_evidence_kind =
                        'generation_runtime_attestation_verification'
                ),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (
                    runtime_attestation_verifier_signature_algorithm =
                        'Ed25519'
                ),
                CHECK (signing_key_id = publication_signing_key_id),
                CHECK (
                    publication_signing_key_id =
                        publication_signing_key_spki_digest
                ),
                CHECK (
                    runtime_attestation_verifier_signing_key_id =
                        runtime_attestation_verifier_signing_key_spki_digest
                ),
                CHECK (assignment_revision > 0),
                CHECK (generation_epoch > 0),
                CHECK (minimum_generation_tombstone_epoch > 0),
                CHECK (
                    minimum_generation_tombstone_epoch <= generation_epoch
                ),
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (publication_revision > 0),
                CHECK (custody_sequence >= 0),
                CHECK (ingress_sequence >= 0),
                CHECK (ingress_range_start_sequence > 0),
                CHECK (ingress_sequence + 1 = ingress_range_start_sequence),
                CHECK (request_commitment_key_epoch > 0),
                CHECK (active_policy_sequence > 0),
                CHECK (active_rollback_epoch > 0),
                CHECK (
                    candidate_policy_sequence > active_policy_sequence
                ),
                CHECK (candidate_rollback_epoch > 0),
                CHECK (active_runtime_snapshot_epoch > 0),
                CHECK (active_policy_trust_generation > 0),
                CHECK (candidate_runtime_snapshot_epoch > 0),
                CHECK (candidate_policy_trust_generation > 0),
                CHECK (attestation_revocation_generation > 0),
                CHECK (replay_store_revision = assignment_revision),
                CHECK (
                    (attestation_mode = 'trusted-host-no-tee'
                        AND NOT hardware_attested)
                    OR (attestation_mode IN (
                            'aws-nitro-enclave', 'amd-sev-snp', 'intel-tdx'
                        ) AND hardware_attested)
                ),
                CHECK (not_before_epoch_ns = issued_at_epoch_ns),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (
                    runtime_attestation_trusted_at_epoch_ns >=
                        runtime_attestation_issued_at_epoch_ns
                ),
                CHECK (
                    runtime_attestation_trusted_at_epoch_ns <
                        runtime_attestation_expires_at_epoch_ns
                ),
                CHECK (length(request_id) = 36),
                CHECK (length(replay_id) BETWEEN 1 AND 256),
                CHECK (length(management_handoff_id) BETWEEN 1 AND 256),
                CHECK (request_id <> replay_id),
                CHECK (request_id <> management_handoff_id),
                CHECK (replay_id <> management_handoff_id),
                CHECK (length(candidate_id) BETWEEN 1 AND 256),
                CHECK (length(canary_id) BETWEEN 1 AND 256),
                CHECK (length(instance_id) BETWEEN 1 AND 256),
                CHECK (length(boot_id) BETWEEN 1 AND 256),
                CHECK (length(management_actor_id) BETWEEN 1 AND 1024),
                CHECK (length(management_request_json) BETWEEN 2 AND 8388608),
                CHECK (
                    length(generation_publication_envelope_json)
                    BETWEEN 2 AND 4194304
                ),
                CHECK (
                    length(generation_publication_payload_json)
                    BETWEEN 2 AND 4194304
                ),
                CHECK (
                    length(runtime_attestation_evidence_json)
                    BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(runtime_attestation_verification_envelope_json)
                    BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(runtime_attestation_verification_payload_json)
                    BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(attestation_chain_json)
                    BETWEEN 2 AND 2097152
                ),
                CHECK (
                    length(generation_evidence_json)
                    BETWEEN 2 AND 2097152
                )
            );

            CREATE TABLE IF NOT EXISTS policy_shadow_generation_activation_publications (
                request_id TEXT PRIMARY KEY,
                replay_id TEXT NOT NULL UNIQUE,
                request_digest TEXT NOT NULL UNIQUE,
                request_json TEXT NOT NULL,
                response_digest TEXT NOT NULL,
                response_json TEXT NOT NULL,
                canary_id TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                generation_id_digest TEXT NOT NULL UNIQUE,
                generation_publication_envelope_digest TEXT NOT NULL,
                activation_publication_envelope_digest TEXT NOT NULL UNIQUE,
                runtime_attestation_verifier_envelope_digest TEXT NOT NULL,
                decision_gate_binding_digest TEXT NOT NULL UNIQUE,
                decision_gate_binding_json TEXT NOT NULL,
                decision_gate_statement_digest TEXT NOT NULL UNIQUE,
                decision_gate_statement_json TEXT NOT NULL,
                evidence_chain_digest TEXT NOT NULL UNIQUE,
                external_evidence_status TEXT NOT NULL,
                trusted_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                actor_id TEXT NOT NULL,
                created_at_epoch_ns BIGINT NOT NULL,
                FOREIGN KEY (
                    generation_publication_envelope_digest
                ) REFERENCES policy_shadow_generation_publications (
                    generation_publication_envelope_digest
                ) ON DELETE RESTRICT,
                CHECK (request_id <> replay_id),
                CHECK (length(request_id) BETWEEN 1 AND 256),
                CHECK (length(replay_id) BETWEEN 1 AND 256),
                CHECK (length(canary_id) BETWEEN 1 AND 256),
                CHECK (length(candidate_id) BETWEEN 1 AND 256),
                CHECK (length(actor_id) BETWEEN 1 AND 1024),
                CHECK (length(request_json) BETWEEN 2 AND 16777216),
                CHECK (length(response_json) BETWEEN 2 AND 16777216),
                CHECK (length(decision_gate_binding_json) BETWEEN 2 AND 4194304),
                CHECK (length(decision_gate_statement_json) BETWEEN 2 AND 16777216),
                CHECK (
                    external_evidence_status IN (
                        'awaiting-external-verifier',
                        'non-production-trusted-host',
                        'verified', 'consumed'
                    )
                ),
                CHECK (trusted_at_epoch_ns > 0),
                CHECK (expires_at_epoch_ns > trusted_at_epoch_ns),
                CHECK (created_at_epoch_ns >= trusted_at_epoch_ns)
            );

            CREATE TABLE IF NOT EXISTS policy_control_plane_exact_results (
                request_id TEXT PRIMARY KEY,
                operation TEXT NOT NULL,
                base_payload_digest TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                response_json TEXT NOT NULL,
                response_digest TEXT NOT NULL UNIQUE,
                created_at_epoch_ns BIGINT NOT NULL,
                CHECK (length(request_id) = 36),
                CHECK (length(operation) BETWEEN 1 AND 128),
                CHECK (length(actor_id) BETWEEN 1 AND 1024),
                CHECK (length(response_json) BETWEEN 2 AND 16777216),
                CHECK (created_at_epoch_ns > 0)
            );

            CREATE TABLE IF NOT EXISTS policy_canary_custody_evidence (
                custody_evidence_envelope_digest TEXT PRIMARY KEY,
                custody_evidence_payload_digest TEXT NOT NULL UNIQUE,
                custody_evidence_id TEXT NOT NULL UNIQUE,
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                assignment_revision BIGINT NOT NULL,
                canary_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                member_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                tee_measurement_digest TEXT NOT NULL,
                runtime_identity_digest TEXT NOT NULL,
                generation_id_digest TEXT NOT NULL,
                custody_sequence BIGINT NOT NULL,
                previous_custody_sequence BIGINT NOT NULL,
                previous_custody_head_digest TEXT NOT NULL,
                resulting_custody_head_digest TEXT NOT NULL UNIQUE,
                ingress_sequence BIGINT NOT NULL,
                request_identity_digest TEXT NOT NULL,
                request_binding_digest TEXT NOT NULL,
                request_commitment_digest TEXT NOT NULL,
                opening_spill_receipt_digest TEXT NOT NULL,
                sampling_decision TEXT NOT NULL,
                persistence_identity_digest TEXT NOT NULL,
                persistence_receipt_digest TEXT NOT NULL,
                immutable_retrieval_proof_digest TEXT NOT NULL,
                trusted_time_epoch_ns BIGINT NOT NULL,
                trusted_time_checkpoint_digest TEXT NOT NULL,
                custody_evidence_envelope_json TEXT NOT NULL,
                custody_evidence_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'custody_evidence',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                created_transition_digest TEXT NOT NULL UNIQUE
                    REFERENCES policy_authority_transition_audits(
                        transition_digest
                    ) ON DELETE RESTRICT,
                UNIQUE (
                    custody_evidence_envelope_digest,
                    verification_receipt_digest
                ),
                UNIQUE (
                    canary_id, instance_id, boot_id, ingress_sequence
                ),
                UNIQUE (
                    assignment_envelope_digest, member_ordinal,
                    generation_id_digest, custody_sequence
                ),
                UNIQUE (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    instance_id, boot_id, generation_id_digest,
                    custody_sequence, resulting_custody_head_digest,
                    custody_evidence_envelope_digest, ingress_sequence
                ),
                UNIQUE (
                    custody_evidence_envelope_digest,
                    custody_evidence_payload_digest,
                    verification_receipt_digest, canary_id, instance_id,
                    boot_id, ingress_sequence
                ),
                FOREIGN KEY (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) REFERENCES policy_canary_instances (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) REFERENCES policy_runtime_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    instance_id, boot_id, generation_id_digest
                ) REFERENCES policy_shadow_generation_publications (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    instance_id, boot_id, generation_id_digest
                ) ON DELETE RESTRICT,
                CHECK (evidence_kind = 'custody_evidence'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (assignment_revision > 0),
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (custody_sequence > 0),
                CHECK (previous_custody_sequence >= 0),
                CHECK (
                    (custody_sequence = 1
                        AND previous_custody_sequence = 0)
                    OR
                    (custody_sequence > 1
                        AND previous_custody_sequence =
                            custody_sequence - 1)
                ),
                CHECK (ingress_sequence > 0),
                CHECK (
                    sampling_decision IN (
                        'included', 'excluded-by-assignment'
                    )
                ),
                CHECK (trusted_time_epoch_ns >= 0),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (
                    length(custody_evidence_envelope_json)
                    BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(custody_evidence_payload_json)
                    BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(created_transition_digest) = 71
                    AND substr(created_transition_digest, 1, 7) = 'sha256:'
                    AND lower(created_transition_digest) =
                        created_transition_digest
                )
            );

            CREATE INDEX IF NOT EXISTS policy_canary_custody_ingress
                ON policy_canary_custody_evidence (
                    canary_id, instance_id, boot_id, ingress_sequence,
                    custody_evidence_envelope_digest,
                    verification_receipt_digest
                );

            CREATE TABLE IF NOT EXISTS policy_canary_custody_heads (
                assignment_envelope_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                canary_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                generation_id_digest TEXT NOT NULL,
                custody_sequence BIGINT NOT NULL,
                custody_head_digest TEXT NOT NULL,
                custody_evidence_envelope_digest TEXT NOT NULL,
                ingress_sequence BIGINT NOT NULL,
                updated_at_epoch_ns BIGINT NOT NULL,
                PRIMARY KEY (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    instance_id, boot_id, generation_id_digest
                ),
                FOREIGN KEY (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    instance_id, boot_id, generation_id_digest,
                    custody_sequence, custody_head_digest,
                    custody_evidence_envelope_digest, ingress_sequence
                ) REFERENCES policy_canary_custody_evidence (
                    assignment_envelope_digest, member_ordinal, canary_id,
                    instance_id, boot_id, generation_id_digest,
                    custody_sequence, resulting_custody_head_digest,
                    custody_evidence_envelope_digest, ingress_sequence
                ) ON DELETE RESTRICT,
                CHECK (member_ordinal > 0),
                CHECK (custody_sequence > 0),
                CHECK (ingress_sequence > 0),
                CHECK (updated_at_epoch_ns >= 0)
            );

            CREATE TABLE IF NOT EXISTS policy_canary_ingress_observations (
                ingress_envelope_digest TEXT PRIMARY KEY,
                ingress_payload_digest TEXT NOT NULL UNIQUE,
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                assignment_revision BIGINT NOT NULL,
                canary_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                member_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                load_receipt_envelope_digest TEXT NOT NULL,
                load_receipt_payload_digest TEXT NOT NULL,
                policy_identity_digest TEXT NOT NULL,
                runtime_identity_digest TEXT NOT NULL,
                ingress_sequence BIGINT NOT NULL,
                observed_at_epoch_ns BIGINT NOT NULL,
                sampling_decision TEXT NOT NULL,
                accounting_outcome TEXT NOT NULL,
                request_commitment_digest TEXT,
                unavailable_marker_digest TEXT,
                custody_generation_id_digest TEXT,
                custody_request_binding_digest TEXT,
                custody_request_commitment_digest TEXT,
                custody_opening_spill_receipt_digest TEXT,
                custody_evidence_envelope_digest TEXT,
                custody_evidence_payload_digest TEXT,
                custody_verification_receipt_digest TEXT,
                ingress_envelope_json TEXT NOT NULL,
                ingress_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'ingress_observation',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                UNIQUE (
                    canary_id, instance_id, boot_id, ingress_sequence
                ),
                UNIQUE (
                    ingress_envelope_digest, ingress_payload_digest,
                    canary_id, instance_id, boot_id, ingress_sequence
                ),
                FOREIGN KEY (
                    canary_id, instance_id, boot_id
                ) REFERENCES policy_canary_instances (
                    canary_id, instance_id, boot_id
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) REFERENCES policy_canary_instances (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    load_receipt_envelope_digest,
                    load_receipt_payload_digest
                ) REFERENCES policy_canary_load_receipts (
                    load_receipt_envelope_digest,
                    load_receipt_payload_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    custody_evidence_envelope_digest,
                    custody_evidence_payload_digest,
                    custody_verification_receipt_digest,
                    canary_id, instance_id, boot_id, ingress_sequence
                ) REFERENCES policy_canary_custody_evidence (
                    custody_evidence_envelope_digest,
                    custody_evidence_payload_digest,
                    verification_receipt_digest,
                    canary_id, instance_id, boot_id, ingress_sequence
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) REFERENCES policy_runtime_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (evidence_kind = 'ingress_observation'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (assignment_revision > 0),
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (ingress_sequence > 0),
                CHECK (
                    sampling_decision IN (
                        'included', 'excluded-by-assignment'
                    )
                ),
                CHECK (
                    accounting_outcome IN (
                        'evaluated', 'dropped', 'error', 'excluded',
                        'transport-excluded'
                    )
                ),
                CHECK (
                    (sampling_decision = 'excluded-by-assignment'
                        AND accounting_outcome = 'excluded')
                    OR
                    (sampling_decision = 'included'
                        AND accounting_outcome IN (
                            'evaluated', 'dropped', 'error',
                            'transport-excluded'
                        ))
                ),
                CHECK (
                    accounting_outcome <> 'excluded'
                    OR (
                        request_commitment_digest IS NOT NULL
                        AND unavailable_marker_digest IS NULL
                    )
                ),
                CHECK (
                    (
                        request_commitment_digest IS NULL
                        AND custody_generation_id_digest IS NULL
                        AND custody_request_binding_digest IS NULL
                        AND custody_request_commitment_digest IS NULL
                        AND custody_opening_spill_receipt_digest IS NULL
                        AND custody_evidence_envelope_digest IS NULL
                        AND custody_evidence_payload_digest IS NULL
                        AND custody_verification_receipt_digest IS NULL
                    )
                    OR
                    (
                        request_commitment_digest IS NOT NULL
                        AND custody_generation_id_digest IS NOT NULL
                        AND custody_request_binding_digest IS NOT NULL
                        AND custody_request_commitment_digest =
                            request_commitment_digest
                        AND custody_opening_spill_receipt_digest IS NOT NULL
                        AND custody_evidence_envelope_digest IS NOT NULL
                        AND custody_evidence_payload_digest IS NOT NULL
                        AND custody_verification_receipt_digest IS NOT NULL
                    )
                ),
                CHECK (
                    custody_generation_id_digest IS NULL
                    OR (
                        length(custody_generation_id_digest) = 71
                        AND substr(
                            custody_generation_id_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(custody_generation_id_digest) =
                            custody_generation_id_digest
                    )
                ),
                CHECK (
                    custody_request_binding_digest IS NULL
                    OR (
                        length(custody_request_binding_digest) = 71
                        AND substr(
                            custody_request_binding_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(custody_request_binding_digest) =
                            custody_request_binding_digest
                    )
                ),
                CHECK (
                    custody_request_commitment_digest IS NULL
                    OR (
                        length(custody_request_commitment_digest) = 71
                        AND substr(
                            custody_request_commitment_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(custody_request_commitment_digest) =
                            custody_request_commitment_digest
                    )
                ),
                CHECK (
                    custody_opening_spill_receipt_digest IS NULL
                    OR (
                        length(
                            custody_opening_spill_receipt_digest
                        ) = 71
                        AND substr(
                            custody_opening_spill_receipt_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(
                            custody_opening_spill_receipt_digest
                        ) = custody_opening_spill_receipt_digest
                    )
                ),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (length(ingress_envelope_json) BETWEEN 2 AND 1048576),
                CHECK (length(ingress_payload_json) BETWEEN 2 AND 1048576)
            );

            CREATE TABLE IF NOT EXISTS policy_canary_active_decisions (
                active_decision_envelope_digest TEXT PRIMARY KEY,
                active_decision_payload_digest TEXT NOT NULL UNIQUE,
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                assignment_revision BIGINT NOT NULL,
                canary_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                member_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                load_receipt_envelope_digest TEXT NOT NULL,
                load_receipt_payload_digest TEXT NOT NULL,
                ingress_envelope_digest TEXT NOT NULL,
                ingress_payload_digest TEXT NOT NULL,
                ingress_sequence BIGINT NOT NULL,
                custody_evidence_envelope_digest TEXT,
                custody_verification_receipt_digest TEXT,
                policy_identity_digest TEXT NOT NULL,
                runtime_identity_digest TEXT NOT NULL,
                generation_id_digest TEXT NOT NULL,
                captured_at_epoch_ns BIGINT NOT NULL,
                decision_at_epoch_ns BIGINT NOT NULL,
                decision_status TEXT NOT NULL,
                active_outcome TEXT NOT NULL,
                active_evaluation_digest TEXT,
                active_unavailable_reason TEXT,
                active_unavailable_marker_digest TEXT,
                final_active_outcome TEXT NOT NULL,
                returned_http_status BIGINT,
                upstream_dispatch_authorized BIGINT NOT NULL,
                active_dispatch_commitment_digest TEXT,
                active_decision_envelope_json TEXT NOT NULL,
                active_decision_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'active_decision',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                UNIQUE (
                    canary_id, instance_id, boot_id, ingress_sequence
                ),
                UNIQUE (
                    active_decision_envelope_digest,
                    active_decision_payload_digest,
                    canary_id, instance_id, boot_id, ingress_sequence
                ),
                FOREIGN KEY (
                    ingress_envelope_digest, ingress_payload_digest,
                    canary_id, instance_id, boot_id, ingress_sequence
                ) REFERENCES policy_canary_ingress_observations (
                    ingress_envelope_digest, ingress_payload_digest,
                    canary_id, instance_id, boot_id, ingress_sequence
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    custody_evidence_envelope_digest,
                    custody_verification_receipt_digest
                ) REFERENCES policy_canary_custody_evidence (
                    custody_evidence_envelope_digest,
                    verification_receipt_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) REFERENCES policy_canary_instances (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) REFERENCES policy_runtime_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (evidence_kind = 'active_decision'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (assignment_revision > 0),
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (ingress_sequence > 0),
                CHECK (
                    (custody_evidence_envelope_digest IS NULL
                        AND custody_verification_receipt_digest IS NULL)
                    OR
                    (custody_evidence_envelope_digest IS NOT NULL
                        AND custody_verification_receipt_digest IS NOT NULL)
                ),
                CHECK (decision_status IN ('evaluated', 'unavailable')),
                CHECK (
                    active_outcome IN (
                        'deny', 'permit', 'conditional', 'indeterminate'
                    )
                ),
                CHECK (
                    final_active_outcome IN (
                        'allow', 'deny', 'conditional', 'error'
                    )
                ),
                CHECK (upstream_dispatch_authorized IN (0, 1)),
                CHECK (
                    final_active_outcome = 'allow'
                    OR upstream_dispatch_authorized = 0
                ),
                CHECK (
                    (decision_status = 'evaluated'
                        AND active_evaluation_digest IS NOT NULL
                        AND active_unavailable_reason IS NULL
                        AND active_unavailable_marker_digest IS NULL
                        AND returned_http_status BETWEEN 100 AND 599
                        AND active_dispatch_commitment_digest IS NOT NULL)
                    OR
                    (decision_status = 'unavailable'
                        AND active_outcome = 'indeterminate'
                        AND final_active_outcome = 'error'
                        AND upstream_dispatch_authorized = 0
                        AND active_evaluation_digest IS NULL
                        AND active_unavailable_reason IS NOT NULL
                        AND active_unavailable_marker_digest IS NOT NULL
                        AND returned_http_status IS NULL
                        AND active_dispatch_commitment_digest IS NULL)
                ),
                CHECK (decision_at_epoch_ns >= captured_at_epoch_ns),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (
                    length(active_decision_envelope_json)
                    BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(active_decision_payload_json)
                    BETWEEN 2 AND 1048576
                )
            );

            CREATE TABLE IF NOT EXISTS policy_canary_shadow_observations (
                shadow_observation_envelope_digest TEXT PRIMARY KEY,
                shadow_observation_payload_digest TEXT NOT NULL UNIQUE,
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                assignment_revision BIGINT NOT NULL,
                canary_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                member_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                load_receipt_envelope_digest TEXT NOT NULL,
                load_receipt_payload_digest TEXT NOT NULL,
                policy_identity_digest TEXT NOT NULL,
                runtime_identity_digest TEXT NOT NULL,
                observation_sequence BIGINT NOT NULL,
                previous_observation_envelope_digest TEXT,
                ingress_envelope_digest TEXT NOT NULL,
                ingress_payload_digest TEXT NOT NULL,
                ingress_sequence BIGINT NOT NULL,
                custody_evidence_envelope_digest TEXT,
                custody_verification_receipt_digest TEXT,
                active_decision_envelope_digest TEXT NOT NULL,
                active_decision_payload_digest TEXT NOT NULL,
                observation_status TEXT NOT NULL,
                active_outcome TEXT NOT NULL,
                candidate_outcome TEXT NOT NULL,
                compiler_analysis_envelope_digest TEXT NOT NULL,
                compiler_analysis_payload_digest TEXT NOT NULL,
                authority_binding_json TEXT NOT NULL,
                authority_binding_digest TEXT NOT NULL,
                route_id TEXT,
                operation_class TEXT,
                request_authority_class TEXT,
                expansion_cells_json TEXT NOT NULL,
                expansion_cells_digest TEXT NOT NULL,
                pilot_membership_json TEXT NOT NULL,
                pilot_membership_digest TEXT NOT NULL,
                candidate_dispatch_commitment_digest TEXT,
                response_obligation_json TEXT NOT NULL,
                response_obligation_digest TEXT NOT NULL,
                response_obligation_route_id TEXT,
                response_obligation_root_digest TEXT,
                response_comparison_json TEXT NOT NULL,
                response_comparison_digest TEXT NOT NULL,
                response_comparison_class TEXT,
                response_capture_mode TEXT,
                latency_samples_json TEXT NOT NULL,
                latency_samples_digest TEXT NOT NULL,
                drop_reason TEXT,
                error_reason TEXT,
                shadow_observation_envelope_json TEXT NOT NULL,
                shadow_observation_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'shadow_observation',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                UNIQUE (
                    canary_id, instance_id, boot_id, observation_sequence
                ),
                UNIQUE (
                    shadow_observation_envelope_digest,
                    shadow_observation_payload_digest,
                    canary_id, instance_id, boot_id, observation_sequence
                ),
                FOREIGN KEY (
                    previous_observation_envelope_digest
                ) REFERENCES policy_canary_shadow_observations (
                    shadow_observation_envelope_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) REFERENCES policy_canary_instances (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    ingress_envelope_digest, ingress_payload_digest,
                    canary_id, instance_id, boot_id, ingress_sequence
                ) REFERENCES policy_canary_ingress_observations (
                    ingress_envelope_digest, ingress_payload_digest,
                    canary_id, instance_id, boot_id, ingress_sequence
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    custody_evidence_envelope_digest,
                    custody_verification_receipt_digest
                ) REFERENCES policy_canary_custody_evidence (
                    custody_evidence_envelope_digest,
                    verification_receipt_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    active_decision_envelope_digest,
                    active_decision_payload_digest,
                    canary_id, instance_id, boot_id, ingress_sequence
                ) REFERENCES policy_canary_active_decisions (
                    active_decision_envelope_digest,
                    active_decision_payload_digest,
                    canary_id, instance_id, boot_id, ingress_sequence
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    compiler_analysis_envelope_digest,
                    compiler_analysis_payload_digest
                ) REFERENCES policy_compiler_authority_analyses (
                    analysis_envelope_digest, analysis_payload_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) REFERENCES policy_runtime_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (evidence_kind = 'shadow_observation'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (assignment_revision > 0),
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (observation_sequence > 0),
                CHECK (
                    (custody_evidence_envelope_digest IS NULL
                        AND custody_verification_receipt_digest IS NULL)
                    OR
                    (custody_evidence_envelope_digest IS NOT NULL
                        AND custody_verification_receipt_digest IS NOT NULL)
                ),
                CHECK (
                    (observation_sequence = 1
                        AND previous_observation_envelope_digest IS NULL)
                    OR
                    (observation_sequence > 1
                        AND previous_observation_envelope_digest IS NOT NULL)
                ),
                CHECK (
                    observation_status IN (
                        'evaluated', 'dropped', 'error', 'excluded',
                        'transport-excluded'
                    )
                ),
                CHECK (
                    active_outcome IN (
                        'deny', 'permit', 'conditional', 'indeterminate'
                    )
                    AND candidate_outcome IN (
                        'deny', 'permit', 'conditional', 'indeterminate'
                    )
                ),
                CHECK (
                    response_comparison_class IS NULL
                    OR response_comparison_class IN (
                        'comparable-identical',
                        'comparable-validation-match',
                        'comparable-validation-divergence',
                        'not-applicable-active-not-dispatched',
                        'not-comparable-candidate-not-dispatchable',
                        'not-comparable-dispatch-commitment-mismatch',
                        'not-comparable-active-response-unavailable',
                        'not-comparable-candidate-validator-unavailable',
                        'not-applicable-both-deny'
                    )
                ),
                CHECK (
                    request_authority_class IS NULL
                    OR request_authority_class IN ('read', 'write')
                ),
                CHECK (
                    operation_class IS NULL
                    OR operation_class IN (
                        'read', 'search', 'write', 'publish', 'delete',
                        'administrative'
                    )
                ),
                CHECK (
                    response_capture_mode IS NULL
                    OR response_capture_mode IN (
                        'bounded-exact', 'streaming-unavailable',
                        'not-dispatched'
                    )
                ),
                CHECK (
                    (
                        observation_status = 'evaluated'
                        AND candidate_dispatch_commitment_digest IS NOT NULL
                        AND response_comparison_class IS NOT NULL
                        AND response_capture_mode IS NOT NULL
                    )
                    OR
                    (
                        observation_status <> 'evaluated'
                        AND candidate_dispatch_commitment_digest IS NULL
                        AND response_comparison_class IS NULL
                        AND response_capture_mode IS NULL
                    )
                ),
                CHECK (
                    (
                        response_obligation_route_id IS NULL
                        AND response_obligation_root_digest IS NULL
                    )
                    OR
                    (
                        response_obligation_route_id IS NOT NULL
                        AND response_obligation_root_digest IS NOT NULL
                    )
                ),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (length(authority_binding_json) BETWEEN 2 AND 1048576),
                CHECK (length(expansion_cells_json) BETWEEN 2 AND 4194304),
                CHECK (length(pilot_membership_json) BETWEEN 2 AND 1048576),
                CHECK (length(response_obligation_json) BETWEEN 2 AND 1048576),
                CHECK (length(response_comparison_json) BETWEEN 2 AND 4194304),
                CHECK (length(latency_samples_json) BETWEEN 2 AND 1048576),
                CHECK (
                    drop_reason IS NULL
                    OR drop_reason IN (
                        'queue-full', 'worker-unavailable',
                        'deadline-exceeded', 'facts-unsupported', 'shutdown'
                    )
                ),
                CHECK (
                    error_reason IS NULL
                    OR error_reason IN (
                        'facts-capture-error', 'active-evaluation-error',
                        'candidate-evaluation-error',
                        'response-validation-error', 'commitment-error',
                        'internal-error'
                    )
                ),
                CHECK (
                    length(shadow_observation_envelope_json)
                    BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(shadow_observation_payload_json)
                    BETWEEN 2 AND 4194304
                )
            );

            CREATE INDEX IF NOT EXISTS policy_canary_shadow_observation_chain
                ON policy_canary_shadow_observations (
                    canary_id, instance_id, boot_id, observation_sequence,
                    previous_observation_envelope_digest
                );

            CREATE TABLE IF NOT EXISTS policy_canary_instance_revisions (
                canary_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                member_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                revision BIGINT NOT NULL,
                status TEXT NOT NULL,
                previous_revision BIGINT,
                previous_status TEXT,
                previous_state_digest TEXT,
                load_receipt_envelope_digest TEXT,
                load_receipt_payload_digest TEXT,
                checkpoint_sequence BIGINT,
                checkpoint_envelope_digest TEXT,
                checkpoint_payload_digest TEXT,
                state_envelope_json TEXT NOT NULL,
                state_payload_json TEXT NOT NULL,
                state_digest TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'canary_instance_state',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                created_at_epoch_ns BIGINT NOT NULL,
                sealed_at_epoch_ns BIGINT,
                terminal_from_status TEXT,
                terminal_at_epoch_ns BIGINT,
                transition_digest TEXT NOT NULL UNIQUE,
                transition_entity_kind TEXT NOT NULL DEFAULT 'canary_instance',
                transition_entity_id TEXT NOT NULL,
                transition_event_type TEXT NOT NULL,
                PRIMARY KEY (canary_id, instance_id, boot_id, revision),
                UNIQUE (
                    canary_id, instance_id, boot_id, revision,
                    state_digest, status
                ),
                FOREIGN KEY (canary_id, instance_id, boot_id)
                    REFERENCES policy_canary_instances (
                        canary_id, instance_id, boot_id
                    ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) REFERENCES policy_canary_instances (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, instance_id, boot_id, previous_revision,
                    previous_state_digest, previous_status
                ) REFERENCES policy_canary_instance_revisions (
                    canary_id, instance_id, boot_id, revision,
                    state_digest, status
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, instance_id, boot_id,
                    load_receipt_envelope_digest,
                    load_receipt_payload_digest
                ) REFERENCES policy_canary_load_receipts (
                    canary_id, instance_id, boot_id,
                    load_receipt_envelope_digest,
                    load_receipt_payload_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    transition_digest, transition_entity_kind,
                    transition_entity_id, revision, state_digest,
                    previous_state_digest, transition_event_type
                ) REFERENCES policy_authority_transition_audits (
                    transition_digest, entity_kind, entity_id,
                    entity_revision, state_digest, previous_state_digest,
                    event_type
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) REFERENCES policy_runtime_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (
                    status IN (
                        'assigned', 'loaded', 'observing', 'sealing',
                        'sealed', 'failed', 'expired'
                    )
                ),
                CHECK (evidence_kind = 'canary_instance_state'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (
                    transition_entity_id =
                        canary_id || '/' || instance_id || '/' || boot_id
                ),
                CHECK (
                    (
                        revision = 1
                        AND status = 'assigned'
                        AND previous_revision IS NULL
                        AND previous_status IS NULL
                        AND previous_state_digest IS NULL
                    )
                    OR (
                        revision > 1
                        AND previous_revision = revision - 1
                        AND previous_status IS NOT NULL
                        AND previous_state_digest IS NOT NULL
                    )
                ),
                CHECK (
                    revision = 1
                    OR (previous_status = 'assigned' AND status IN (
                        'loaded', 'failed', 'expired'
                    ))
                    OR (previous_status = 'loaded' AND status IN (
                        'observing', 'failed', 'expired'
                    ))
                    OR (previous_status = 'observing' AND status IN (
                        'sealing', 'failed', 'expired'
                    ))
                    OR (previous_status = 'sealing' AND status IN (
                        'sealed', 'failed', 'expired'
                    ))
                ),
                CHECK (
                    (
                        load_receipt_envelope_digest IS NULL
                        AND load_receipt_payload_digest IS NULL
                    )
                    OR (
                        load_receipt_envelope_digest IS NOT NULL
                        AND load_receipt_payload_digest IS NOT NULL
                    )
                ),
                CHECK (
                    status = 'assigned'
                    OR (
                        load_receipt_envelope_digest IS NOT NULL
                        AND load_receipt_payload_digest IS NOT NULL
                    )
                ),
                CHECK (
                    (
                        checkpoint_sequence IS NULL
                        AND checkpoint_envelope_digest IS NULL
                        AND checkpoint_payload_digest IS NULL
                    )
                    OR (
                        checkpoint_sequence IS NOT NULL
                        AND checkpoint_sequence > 0
                        AND checkpoint_envelope_digest IS NOT NULL
                        AND checkpoint_payload_digest IS NOT NULL
                    )
                ),
                CHECK (created_at_epoch_ns >= 0),
                CHECK (
                    sealed_at_epoch_ns IS NULL
                    OR sealed_at_epoch_ns >= created_at_epoch_ns
                ),
                CHECK (
                    (
                        status IN ('sealed', 'failed', 'expired')
                        AND terminal_from_status = previous_status
                        AND terminal_at_epoch_ns IS NOT NULL
                        AND terminal_at_epoch_ns >= created_at_epoch_ns
                    )
                    OR (
                        status NOT IN ('sealed', 'failed', 'expired')
                        AND terminal_from_status IS NULL
                        AND terminal_at_epoch_ns IS NULL
                    )
                ),
                CHECK (
                    status <> 'sealed'
                    OR (
                        checkpoint_sequence IS NOT NULL
                        AND sealed_at_epoch_ns IS NOT NULL
                    )
                ),
                CHECK (transition_entity_kind = 'canary_instance'),
                CHECK (length(state_envelope_json) BETWEEN 2 AND 1048576),
                CHECK (length(state_payload_json) BETWEEN 2 AND 1048576),
                CHECK (length(signing_key_id) BETWEEN 1 AND 1024),
                CHECK (length(signature) BETWEEN 1 AND 4096)
            );

            CREATE INDEX IF NOT EXISTS policy_instance_revisions_predecessor
                ON policy_canary_instance_revisions (
                    canary_id, instance_id, boot_id, previous_revision,
                    previous_state_digest
                );

            CREATE TABLE IF NOT EXISTS policy_canary_instance_heads (
                canary_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                head_revision BIGINT NOT NULL,
                head_state_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                updated_at_epoch_ns BIGINT NOT NULL,
                PRIMARY KEY (canary_id, instance_id, boot_id),
                FOREIGN KEY (
                    canary_id, instance_id, boot_id, head_revision,
                    head_state_digest, status
                ) REFERENCES policy_canary_instance_revisions (
                    canary_id, instance_id, boot_id, revision,
                    state_digest, status
                ) ON DELETE RESTRICT,
                CHECK (head_revision > 0),
                CHECK (updated_at_epoch_ns >= 0)
            );

            CREATE TABLE IF NOT EXISTS policy_canary_checkpoints (
                canary_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                membership_revision BIGINT NOT NULL,
                membership_root_digest TEXT NOT NULL,
                member_ordinal BIGINT NOT NULL,
                member_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                checkpoint_sequence BIGINT NOT NULL,
                checkpoint_envelope_digest TEXT NOT NULL,
                checkpoint_payload_digest TEXT NOT NULL UNIQUE,
                predecessor_checkpoint_sequence BIGINT,
                previous_checkpoint_digest TEXT NOT NULL,
                previous_observation_digest TEXT NOT NULL,
                previous_ingress_root_digest TEXT NOT NULL,
                previous_active_decision_root_digest TEXT NOT NULL,
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                assignment_revision BIGINT NOT NULL,
                load_receipt_envelope_digest TEXT NOT NULL,
                load_receipt_payload_digest TEXT NOT NULL,
                policy_identity_digest TEXT NOT NULL,
                runtime_identity_digest TEXT NOT NULL,
                artifact_envelope_digest TEXT NOT NULL,
                artifact_payload_digest TEXT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                compiler_digest TEXT NOT NULL,
                compiler_config_digest TEXT NOT NULL,
                policy_schema_digest TEXT NOT NULL,
                semantic_model_digest TEXT NOT NULL,
                evaluator_abi_digest TEXT NOT NULL,
                policy_bundle_digest TEXT NOT NULL,
                runtime_digest TEXT NOT NULL,
                boot_public_key_digest TEXT NOT NULL,
                boot_signing_key_id TEXT NOT NULL,
                request_sequence_start BIGINT NOT NULL,
                request_sequence_end BIGINT NOT NULL,
                previous_request_sequence_end BIGINT NOT NULL,
                observation_sequence_start BIGINT NOT NULL,
                observation_sequence_end BIGINT NOT NULL,
                previous_observation_sequence_end BIGINT NOT NULL,
                first_observation_envelope_digest TEXT NOT NULL,
                last_observation_envelope_digest TEXT NOT NULL,
                first_observed_at_epoch_ns BIGINT NOT NULL,
                last_observed_at_epoch_ns BIGINT NOT NULL,
                observed_request_count BIGINT NOT NULL,
                ingress_count BIGINT NOT NULL,
                verified_evidence_bytes BIGINT NOT NULL,
                verification_work_units BIGINT NOT NULL,
                evaluated_request_count BIGINT NOT NULL,
                dropped_request_count BIGINT NOT NULL,
                evaluation_error_count BIGINT NOT NULL,
                excluded_request_count BIGINT NOT NULL,
                active_permit_count BIGINT NOT NULL,
                active_deny_count BIGINT NOT NULL,
                active_conditional_count BIGINT NOT NULL,
                active_indeterminate_count BIGINT NOT NULL,
                candidate_permit_count BIGINT NOT NULL,
                candidate_deny_count BIGINT NOT NULL,
                candidate_conditional_count BIGINT NOT NULL,
                candidate_indeterminate_count BIGINT NOT NULL,
                observation_root_digest TEXT NOT NULL,
                ingress_root_digest TEXT NOT NULL,
                active_decision_root_digest TEXT NOT NULL,
                custody_evidence_root_digest TEXT NOT NULL,
                custody_verification_root_digest TEXT NOT NULL,
                principal_authority_root_digest TEXT NOT NULL,
                route_authority_root_digest TEXT NOT NULL,
                heartbeat_evidence_json TEXT NOT NULL,
                heartbeat_evidence_digest TEXT NOT NULL,
                checkpoint_envelope_json TEXT NOT NULL,
                checkpoint_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'checkpoint',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                window_started_at_epoch_ns BIGINT NOT NULL,
                window_ended_at_epoch_ns BIGINT NOT NULL,
                created_transition_digest TEXT NOT NULL UNIQUE
                    REFERENCES policy_authority_transition_audits(transition_digest)
                    ON DELETE RESTRICT,
                PRIMARY KEY (
                    canary_id, instance_id, boot_id, checkpoint_sequence
                ),
                UNIQUE (
                    canary_id, instance_id, boot_id, checkpoint_sequence,
                    checkpoint_envelope_digest, observation_root_digest,
                    request_sequence_end, observation_sequence_end
                ),
                UNIQUE (
                    canary_id, instance_id, boot_id, checkpoint_sequence,
                    checkpoint_envelope_digest, observation_root_digest,
                    ingress_root_digest, active_decision_root_digest,
                    request_sequence_end, observation_sequence_end
                ),
                UNIQUE (
                    canary_id, instance_id, boot_id, checkpoint_sequence,
                    checkpoint_envelope_digest, checkpoint_payload_digest
                ),
                FOREIGN KEY (
                    canary_id, instance_id, boot_id,
                    load_receipt_envelope_digest,
                    load_receipt_payload_digest,
                    assignment_envelope_digest, assignment_payload_digest,
                    artifact_envelope_digest, artifact_payload_digest,
                    candidate_policy_hash, compiler_digest,
                    compiler_config_digest, policy_schema_digest,
                    semantic_model_digest, evaluator_abi_digest,
                    policy_bundle_digest, runtime_digest,
                    boot_public_key_digest, boot_signing_key_id
                ) REFERENCES policy_canary_load_receipts (
                    canary_id, instance_id, boot_id,
                    load_receipt_envelope_digest,
                    load_receipt_payload_digest,
                    assignment_envelope_digest, assignment_payload_digest,
                    artifact_envelope_digest, artifact_payload_digest,
                    candidate_policy_hash, compiler_digest,
                    compiler_config_digest, policy_schema_digest,
                    semantic_model_digest, evaluator_abi_digest,
                    policy_bundle_digest, runtime_digest,
                    boot_public_key_digest, boot_signing_key_id
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, instance_id, boot_id,
                    predecessor_checkpoint_sequence,
                    previous_checkpoint_digest,
                    previous_observation_digest,
                    previous_ingress_root_digest,
                    previous_active_decision_root_digest,
                    previous_request_sequence_end,
                    previous_observation_sequence_end
                ) REFERENCES policy_canary_checkpoints (
                    canary_id, instance_id, boot_id, checkpoint_sequence,
                    checkpoint_envelope_digest, observation_root_digest,
                    ingress_root_digest, active_decision_root_digest,
                    request_sequence_end, observation_sequence_end
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) REFERENCES policy_canary_instances (
                    canary_id, member_ordinal, member_id,
                    instance_id, boot_id
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) REFERENCES policy_runtime_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    assignment_envelope_digest, member_ordinal,
                    signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (checkpoint_sequence > 0),
                CHECK (membership_revision > 0),
                CHECK (member_ordinal > 0),
                CHECK (assignment_revision > 0),
                CHECK (
                    (
                        checkpoint_sequence = 1
                        AND predecessor_checkpoint_sequence IS NULL
                        AND previous_checkpoint_digest =
                            assignment_payload_digest
                        AND previous_observation_digest =
                            load_receipt_payload_digest
                        AND request_sequence_start > 0
                        AND previous_request_sequence_end =
                            request_sequence_start - 1
                        AND observation_sequence_start = 1
                        AND previous_observation_sequence_end = 0
                    )
                    OR (
                        checkpoint_sequence > 1
                        AND predecessor_checkpoint_sequence =
                            checkpoint_sequence - 1
                        AND request_sequence_start > 0
                        AND previous_request_sequence_end >=
                            request_sequence_start
                        AND request_sequence_end >
                            previous_request_sequence_end
                        AND observation_sequence_start = 1
                        AND previous_observation_sequence_end > 0
                        AND observation_sequence_end >
                            previous_observation_sequence_end
                    )
                ),
                CHECK (evidence_kind = 'checkpoint'),
                CHECK (
                    length(heartbeat_evidence_json)
                    BETWEEN 2 AND 8388608
                ),
                CHECK (request_sequence_end >= request_sequence_start),
                CHECK (
                    observation_sequence_end >= observation_sequence_start
                ),
                CHECK (
                    observed_request_count =
                        request_sequence_end - request_sequence_start + 1
                ),
                CHECK (
                    observed_request_count = observation_sequence_end
                ),
                CHECK (ingress_count = observed_request_count),
                CHECK (
                    verified_evidence_bytes > 0
                    AND verified_evidence_bytes <= 67108864
                ),
                CHECK (
                    verification_work_units =
                        observed_request_count * 16
                ),
                CHECK (
                    first_observed_at_epoch_ns >= 0
                    AND last_observed_at_epoch_ns >=
                        first_observed_at_epoch_ns
                ),
                CHECK (
                    observed_request_count =
                        evaluated_request_count + dropped_request_count +
                        evaluation_error_count + excluded_request_count
                ),
                CHECK (
                    evaluated_request_count =
                        active_permit_count + active_deny_count +
                        active_conditional_count + active_indeterminate_count
                ),
                CHECK (
                    evaluated_request_count =
                        candidate_permit_count + candidate_deny_count +
                        candidate_conditional_count +
                        candidate_indeterminate_count
                ),
                CHECK (
                    observed_request_count > 0
                    AND evaluated_request_count >= 0
                    AND dropped_request_count >= 0
                    AND evaluation_error_count >= 0
                    AND excluded_request_count >= 0
                ),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (window_started_at_epoch_ns >= 0),
                CHECK (window_ended_at_epoch_ns >= window_started_at_epoch_ns),
                CHECK (length(checkpoint_envelope_json) BETWEEN 2 AND 1048576),
                CHECK (length(checkpoint_payload_json) BETWEEN 2 AND 1048576),
                CHECK (length(signing_key_id) BETWEEN 1 AND 1024),
                CHECK (length(signature) BETWEEN 1 AND 4096)
            );

            CREATE INDEX IF NOT EXISTS policy_checkpoints_predecessor
                ON policy_canary_checkpoints (
                    canary_id, instance_id, boot_id,
                    predecessor_checkpoint_sequence
                );

            CREATE TABLE IF NOT EXISTS policy_canary_checkpoint_aggregates (
                canary_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                checkpoint_sequence BIGINT NOT NULL,
                checkpoint_envelope_digest TEXT NOT NULL,
                checkpoint_payload_digest TEXT NOT NULL,
                observation_count BIGINT NOT NULL,
                ingress_sequence_end BIGINT NOT NULL,
                observation_sequence_end BIGINT NOT NULL,
                cumulative_observation_root_digest TEXT NOT NULL,
                cumulative_ingress_root_digest TEXT NOT NULL,
                cumulative_active_decision_root_digest TEXT NOT NULL,
                cumulative_custody_evidence_root_digest TEXT NOT NULL,
                cumulative_custody_verification_root_digest TEXT NOT NULL,
                aggregate_counters_json TEXT NOT NULL,
                aggregate_counters_digest TEXT NOT NULL,
                semantic_matrix_json TEXT NOT NULL,
                semantic_matrix_digest TEXT NOT NULL,
                expansion_cells_json TEXT NOT NULL,
                expansion_cells_digest TEXT NOT NULL,
                response_route_coverage_json TEXT NOT NULL,
                response_route_coverage_digest TEXT NOT NULL,
                latency_histograms_json TEXT NOT NULL,
                latency_histograms_digest TEXT NOT NULL,
                drop_counters_json TEXT NOT NULL,
                drop_counters_digest TEXT NOT NULL,
                error_counters_json TEXT NOT NULL,
                error_counters_digest TEXT NOT NULL,
                excluded_count BIGINT NOT NULL,
                gap_count BIGINT NOT NULL,
                indeterminate_count BIGINT NOT NULL,
                response_divergence_count BIGINT NOT NULL,
                response_validator_unavailable_count BIGINT NOT NULL,
                sealed BIGINT NOT NULL,
                window_closure_envelope_digest TEXT,
                seal_root_digest TEXT,
                sealed_at_epoch_ns BIGINT,
                aggregate_contract_digest TEXT NOT NULL UNIQUE,
                PRIMARY KEY (
                    canary_id, instance_id, boot_id, checkpoint_sequence
                ),
                FOREIGN KEY (
                    canary_id, instance_id, boot_id, checkpoint_sequence,
                    checkpoint_envelope_digest, checkpoint_payload_digest
                ) REFERENCES policy_canary_checkpoints (
                    canary_id, instance_id, boot_id, checkpoint_sequence,
                    checkpoint_envelope_digest, checkpoint_payload_digest
                ) ON DELETE RESTRICT,
                CHECK (checkpoint_sequence > 0),
                CHECK (observation_count > 0),
                CHECK (ingress_sequence_end > 0),
                CHECK (observation_sequence_end > 0),
                CHECK (
                    excluded_count >= 0
                    AND gap_count >= 0
                    AND indeterminate_count >= 0
                    AND response_divergence_count >= 0
                    AND response_validator_unavailable_count >= 0
                ),
                CHECK (
                    (sealed = 0
                        AND window_closure_envelope_digest IS NULL
                        AND seal_root_digest IS NULL
                        AND sealed_at_epoch_ns IS NULL)
                    OR
                    (sealed = 1
                        AND window_closure_envelope_digest IS NOT NULL
                        AND seal_root_digest IS NOT NULL
                        AND sealed_at_epoch_ns IS NOT NULL)
                ),
                CHECK (length(aggregate_counters_json) BETWEEN 2 AND 4194304),
                CHECK (length(semantic_matrix_json) BETWEEN 2 AND 1048576),
                CHECK (length(expansion_cells_json) BETWEEN 2 AND 4194304),
                CHECK (
                    length(response_route_coverage_json)
                    BETWEEN 2 AND 4194304
                ),
                CHECK (length(latency_histograms_json) BETWEEN 2 AND 1048576),
                CHECK (length(drop_counters_json) BETWEEN 2 AND 1048576),
                CHECK (length(error_counters_json) BETWEEN 2 AND 1048576)
            );

            CREATE TABLE IF NOT EXISTS policy_canary_checkpoint_heads (
                canary_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                checkpoint_sequence BIGINT NOT NULL,
                checkpoint_envelope_digest TEXT NOT NULL,
                checkpoint_payload_digest TEXT NOT NULL,
                observation_root_digest TEXT NOT NULL,
                request_sequence_end BIGINT NOT NULL,
                observation_sequence_end BIGINT NOT NULL,
                sealed BIGINT NOT NULL DEFAULT 0,
                sealed_at_epoch_ns BIGINT,
                updated_at_epoch_ns BIGINT NOT NULL,
                PRIMARY KEY (canary_id, instance_id, boot_id),
                FOREIGN KEY (
                    canary_id, instance_id, boot_id, checkpoint_sequence,
                    checkpoint_envelope_digest, observation_root_digest,
                    request_sequence_end, observation_sequence_end
                ) REFERENCES policy_canary_checkpoints (
                    canary_id, instance_id, boot_id, checkpoint_sequence,
                    checkpoint_envelope_digest, observation_root_digest,
                    request_sequence_end, observation_sequence_end
                ) ON DELETE RESTRICT,
                FOREIGN KEY (checkpoint_payload_digest)
                    REFERENCES policy_canary_checkpoints(
                        checkpoint_payload_digest
                    ) ON DELETE RESTRICT,
                CHECK (checkpoint_sequence > 0),
                CHECK (sealed IN (0, 1)),
                CHECK (
                    (sealed = 0 AND sealed_at_epoch_ns IS NULL)
                    OR (
                        sealed = 1
                        AND sealed_at_epoch_ns IS NOT NULL
                        AND sealed_at_epoch_ns >= updated_at_epoch_ns
                    )
                )
            );

            CREATE TABLE IF NOT EXISTS policy_canary_readiness (
                readiness_envelope_digest TEXT PRIMARY KEY,
                readiness_payload_digest TEXT NOT NULL UNIQUE,
                canary_id TEXT NOT NULL,
                predecessor_canary_revision BIGINT NOT NULL,
                predecessor_canary_state_digest TEXT NOT NULL,
                designated_ready_revision BIGINT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ready',
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                artifact_envelope_digest TEXT NOT NULL,
                artifact_payload_digest TEXT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                candidate_policy_sequence BIGINT NOT NULL,
                candidate_rollback_epoch BIGINT NOT NULL,
                predecessor_policy_hash TEXT NOT NULL,
                compiler_digest TEXT NOT NULL,
                compiler_config_digest TEXT NOT NULL,
                policy_schema_digest TEXT NOT NULL,
                semantic_model_digest TEXT NOT NULL,
                evaluator_abi_digest TEXT NOT NULL,
                policy_bundle_digest TEXT NOT NULL,
                runtime_digest TEXT NOT NULL,
                thresholds_digest TEXT NOT NULL,
                compiler_analysis_envelope_digest TEXT NOT NULL,
                compiler_analysis_payload_digest TEXT NOT NULL,
                authority_analysis_mode TEXT NOT NULL,
                approval_mode TEXT NOT NULL,
                required_approval_quorum BIGINT NOT NULL,
                readiness_core_digest TEXT NOT NULL,
                activation_context_digest TEXT NOT NULL,
                publication_revision BIGINT NOT NULL,
                expected_active_policy_sequence BIGINT NOT NULL,
                expected_active_rollback_epoch BIGINT NOT NULL,
                semantic_matrix_digest TEXT NOT NULL,
                expansion_cells_digest TEXT NOT NULL,
                response_route_coverage_digest TEXT NOT NULL,
                latency_histograms_digest TEXT NOT NULL,
                aggregate_counters_digest TEXT NOT NULL,
                response_obligations_digest TEXT NOT NULL,
                sealed_checkpoint_root_digest TEXT NOT NULL,
                sealed_instance_set_digest TEXT NOT NULL,
                expected_instance_count BIGINT NOT NULL,
                sealed_instance_count BIGINT NOT NULL,
                observed_request_count BIGINT NOT NULL,
                evaluated_request_count BIGINT NOT NULL,
                dropped_request_count BIGINT NOT NULL,
                evaluation_error_count BIGINT NOT NULL,
                excluded_request_count BIGINT NOT NULL,
                expansion_approval_context_digest TEXT,
                readiness_envelope_json TEXT NOT NULL,
                readiness_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'readiness',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                created_transition_digest TEXT NOT NULL UNIQUE
                    REFERENCES policy_authority_transition_audits(transition_digest)
                    ON DELETE RESTRICT,
                UNIQUE (canary_id, designated_ready_revision),
                UNIQUE (
                    readiness_envelope_digest, readiness_payload_digest,
                    canary_id, predecessor_canary_revision,
                    predecessor_canary_state_digest,
                    designated_ready_revision,
                    artifact_envelope_digest, artifact_payload_digest,
                    candidate_policy_hash, predecessor_policy_hash,
                    thresholds_digest, sealed_checkpoint_root_digest,
                    sealed_instance_set_digest
                ),
                UNIQUE (
                    readiness_envelope_digest, readiness_payload_digest,
                    canary_id, candidate_policy_hash,
                    candidate_policy_sequence, candidate_rollback_epoch,
                    predecessor_policy_hash
                ),
                UNIQUE (
                    readiness_envelope_digest, readiness_payload_digest,
                    canary_id, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    candidate_policy_sequence, candidate_rollback_epoch,
                    predecessor_policy_hash
                ),
                FOREIGN KEY (
                    canary_id, predecessor_canary_revision,
                    predecessor_canary_state_digest
                ) REFERENCES policy_canary_revisions (
                    canary_id, revision, state_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    canary_id, assignment_envelope_digest,
                    assignment_payload_digest, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    compiler_digest, compiler_config_digest,
                    policy_schema_digest, semantic_model_digest,
                    evaluator_abi_digest, policy_bundle_digest,
                    runtime_digest
                ) REFERENCES policy_canary_assignments (
                    canary_id, assignment_envelope_digest,
                    assignment_payload_digest, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    compiler_digest, compiler_config_digest,
                    policy_schema_digest, semantic_model_digest,
                    evaluator_abi_digest, policy_bundle_digest,
                    runtime_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) REFERENCES policy_authority_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    compiler_analysis_envelope_digest,
                    compiler_analysis_payload_digest
                ) REFERENCES policy_compiler_authority_analyses (
                    analysis_envelope_digest, analysis_payload_digest
                ) ON DELETE RESTRICT,
                CHECK (evidence_kind = 'readiness'),
                CHECK (status = 'ready'),
                CHECK (predecessor_canary_revision > 0),
                CHECK (
                    designated_ready_revision =
                        predecessor_canary_revision + 1
                ),
                CHECK (publication_revision > 0),
                CHECK (expected_active_policy_sequence > 0),
                CHECK (expected_active_rollback_epoch >= 0),
                CHECK (
                    (authority_analysis_mode = 'no-expansion'
                        AND approval_mode = 'none'
                        AND required_approval_quorum = 1
                        AND expansion_approval_context_digest IS NULL)
                    OR
                    (authority_analysis_mode = 'approved-expansion'
                        AND approval_mode IN (
                            'single-person-hardware-webauthn',
                            'two-person-hardware-webauthn'
                        )
                        AND required_approval_quorum IN (1, 2)
                        AND expansion_approval_context_digest IS NOT NULL)
                ),
                CHECK (expected_instance_count > 0),
                CHECK (sealed_instance_count = expected_instance_count),
                CHECK (observed_request_count > 0),
                CHECK (
                    observed_request_count =
                        evaluated_request_count + dropped_request_count +
                        evaluation_error_count + excluded_request_count
                ),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (issued_at_epoch_ns >= 0),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (length(readiness_envelope_json) BETWEEN 2 AND 1048576),
                CHECK (length(readiness_payload_json) BETWEEN 2 AND 1048576),
                CHECK (length(signing_key_id) BETWEEN 1 AND 1024),
                CHECK (length(signature) BETWEEN 1 AND 4096),
                CHECK (
                    expansion_approval_context_digest IS NULL
                    OR (
                        length(expansion_approval_context_digest) = 71
                        AND substr(
                            expansion_approval_context_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(expansion_approval_context_digest) =
                            expansion_approval_context_digest
                    )
                )
            );

            CREATE TABLE IF NOT EXISTS policy_activation_approvals (
                approval_id TEXT PRIMARY KEY,
                approval_context_digest TEXT NOT NULL UNIQUE,
                readiness_envelope_digest TEXT NOT NULL,
                readiness_payload_digest TEXT NOT NULL UNIQUE,
                readiness_core_digest TEXT NOT NULL,
                compiler_analysis_payload_digest TEXT NOT NULL,
                authority_analysis_mode TEXT NOT NULL,
                approval_mode TEXT NOT NULL,
                expansion_cells_digest TEXT NOT NULL,
                publication_revision BIGINT NOT NULL,
                expected_active_policy_sequence BIGINT NOT NULL,
                expected_active_rollback_epoch BIGINT NOT NULL,
                activation_intent_digest TEXT NOT NULL UNIQUE,
                canary_id TEXT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                candidate_policy_sequence BIGINT NOT NULL,
                candidate_rollback_epoch BIGINT NOT NULL,
                predecessor_policy_hash TEXT NOT NULL,
                requester_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                required_member_count BIGINT NOT NULL,
                use_limit BIGINT NOT NULL,
                webauthn_challenge_context_digest TEXT NOT NULL,
                aggregate_evidence_digest TEXT NOT NULL UNIQUE,
                approval_context_json TEXT NOT NULL,
                aggregate_evidence_json TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_transition_digest TEXT NOT NULL UNIQUE
                    REFERENCES policy_authority_transition_audits(transition_digest)
                    ON DELETE RESTRICT,
                FOREIGN KEY (
                    readiness_envelope_digest, readiness_payload_digest,
                    canary_id, candidate_policy_hash,
                    candidate_policy_sequence, candidate_rollback_epoch,
                    predecessor_policy_hash
                ) REFERENCES policy_canary_readiness (
                    readiness_envelope_digest, readiness_payload_digest,
                    canary_id, candidate_policy_hash,
                    candidate_policy_sequence, candidate_rollback_epoch,
                    predecessor_policy_hash
                ) ON DELETE RESTRICT,
                UNIQUE (
                    approval_id, readiness_payload_digest,
                    activation_intent_digest,
                    approval_context_digest
                ),
                CHECK (action = 'policy.candidate.activate'),
                CHECK (resource_id = canary_id),
                CHECK (payload_digest = approval_context_digest),
                CHECK (required_member_count IN (1, 2)),
                CHECK (
                    (approval_mode = 'none'
                        AND authority_analysis_mode = 'no-expansion'
                        AND required_member_count = 1)
                    OR
                    (approval_mode = 'single-person-hardware-webauthn'
                        AND authority_analysis_mode = 'approved-expansion'
                        AND required_member_count = 1)
                    OR
                    (approval_mode = 'two-person-hardware-webauthn'
                        AND authority_analysis_mode = 'approved-expansion'
                        AND required_member_count = 2)
                ),
                CHECK (publication_revision > 0),
                CHECK (expected_active_policy_sequence > 0),
                CHECK (expected_active_rollback_epoch >= 0),
                CHECK (use_limit = 1),
                CHECK (approval_id = aggregate_evidence_digest),
                CHECK (length(requester_id) BETWEEN 1 AND 1024),
                CHECK (length(approval_context_json) BETWEEN 2 AND 1048576),
                CHECK (length(aggregate_evidence_json) BETWEEN 2 AND 1048576),
                CHECK (
                    length(approval_id) = 71
                    AND substr(approval_id, 1, 7) = 'sha256:'
                    AND lower(approval_id) = approval_id
                ),
                CHECK (
                    length(approval_context_digest) = 71
                    AND substr(approval_context_digest, 1, 7) = 'sha256:'
                    AND lower(approval_context_digest) =
                        approval_context_digest
                )
            );

            CREATE TABLE IF NOT EXISTS policy_activation_rollback_authorities (
                rollback_authorization_envelope_digest TEXT PRIMARY KEY,
                rollback_authorization_payload_digest TEXT NOT NULL UNIQUE,
                readiness_envelope_digest TEXT NOT NULL,
                readiness_payload_digest TEXT NOT NULL,
                readiness_core_digest TEXT NOT NULL,
                canary_id TEXT NOT NULL,
                artifact_envelope_digest TEXT NOT NULL,
                artifact_payload_digest TEXT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                candidate_policy_sequence BIGINT NOT NULL,
                candidate_rollback_epoch BIGINT NOT NULL,
                predecessor_policy_hash TEXT NOT NULL,
                expected_active_policy_sequence BIGINT NOT NULL,
                expected_active_rollback_epoch BIGINT NOT NULL,
                publication_revision BIGINT NOT NULL,
                approval_context_digest TEXT NOT NULL,
                webauthn_challenge_context_digest TEXT NOT NULL,
                expected_high_water_digest TEXT NOT NULL,
                rollback_authorization_envelope_json TEXT NOT NULL,
                rollback_authorization_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'rollback_authority',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                issued_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                use_limit BIGINT NOT NULL,
                UNIQUE (
                    rollback_authorization_envelope_digest,
                    rollback_authorization_payload_digest
                ),
                FOREIGN KEY (
                    readiness_envelope_digest, readiness_payload_digest,
                    canary_id, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    candidate_policy_sequence, candidate_rollback_epoch,
                    predecessor_policy_hash
                ) REFERENCES policy_canary_readiness (
                    readiness_envelope_digest, readiness_payload_digest,
                    canary_id, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    candidate_policy_sequence, candidate_rollback_epoch,
                    predecessor_policy_hash
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) REFERENCES policy_authority_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (evidence_kind = 'rollback_authority'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (candidate_policy_sequence > 0),
                CHECK (candidate_rollback_epoch > expected_active_rollback_epoch),
                CHECK (expected_active_policy_sequence > 0),
                CHECK (expected_active_rollback_epoch >= 0),
                CHECK (publication_revision > 0),
                CHECK (use_limit = 1),
                CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
                CHECK (
                    length(rollback_authorization_envelope_json)
                    BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(rollback_authorization_payload_json)
                    BETWEEN 2 AND 1048576
                )
            );

            CREATE TABLE IF NOT EXISTS
                policy_activation_rollback_authority_revocations (
                    revocation_envelope_digest TEXT PRIMARY KEY,
                    revocation_payload_digest TEXT NOT NULL UNIQUE,
                    rollback_authorization_envelope_digest TEXT NOT NULL,
                    rollback_authorization_payload_digest TEXT NOT NULL UNIQUE,
                    readiness_envelope_digest TEXT NOT NULL,
                    readiness_payload_digest TEXT NOT NULL,
                    readiness_core_digest TEXT NOT NULL,
                    canary_id TEXT NOT NULL,
                    artifact_envelope_digest TEXT NOT NULL,
                    artifact_payload_digest TEXT NOT NULL,
                    candidate_policy_hash TEXT NOT NULL,
                    candidate_policy_sequence BIGINT NOT NULL,
                    candidate_rollback_epoch BIGINT NOT NULL,
                    predecessor_policy_hash TEXT NOT NULL,
                    expected_active_policy_sequence BIGINT NOT NULL,
                    expected_active_rollback_epoch BIGINT NOT NULL,
                    publication_revision BIGINT NOT NULL,
                    approval_context_digest TEXT NOT NULL,
                    webauthn_challenge_context_digest TEXT NOT NULL,
                    expected_high_water_digest TEXT NOT NULL,
                    revocation_reason_digest TEXT NOT NULL,
                    revoked_by TEXT NOT NULL,
                    revoked_at_epoch_ns BIGINT NOT NULL,
                    revocation_envelope_json TEXT NOT NULL,
                    revocation_payload_json TEXT NOT NULL,
                    signature_algorithm TEXT NOT NULL,
                    signing_key_id TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    signature_digest TEXT NOT NULL UNIQUE,
                    evidence_kind TEXT NOT NULL DEFAULT
                        'rollback_authority_revocation',
                    record_binding_digest TEXT NOT NULL UNIQUE,
                    verification_receipt_digest TEXT NOT NULL UNIQUE,
                    created_transition_digest TEXT NOT NULL UNIQUE
                        REFERENCES policy_authority_transition_audits(
                            transition_digest
                        ) ON DELETE RESTRICT,
                    FOREIGN KEY (
                        rollback_authorization_envelope_digest,
                        rollback_authorization_payload_digest
                    ) REFERENCES policy_activation_rollback_authorities (
                        rollback_authorization_envelope_digest,
                        rollback_authorization_payload_digest
                    ) ON DELETE RESTRICT,
                    FOREIGN KEY (
                        verification_receipt_digest, evidence_kind,
                        signing_key_id, signature_digest,
                        record_binding_digest
                    ) REFERENCES policy_authority_evidence_verifications (
                        verification_receipt_digest, evidence_kind,
                        signing_key_id, signature_digest,
                        record_binding_digest
                    ) ON DELETE RESTRICT,
                    CHECK (
                        evidence_kind =
                            'rollback_authority_revocation'
                    ),
                    CHECK (signature_algorithm = 'Ed25519'),
                    CHECK (candidate_policy_sequence > 0),
                    CHECK (
                        candidate_rollback_epoch >
                            expected_active_rollback_epoch
                    ),
                    CHECK (expected_active_policy_sequence > 0),
                    CHECK (expected_active_rollback_epoch >= 0),
                    CHECK (publication_revision > 0),
                    CHECK (revoked_at_epoch_ns >= 0),
                    CHECK (length(revoked_by) BETWEEN 1 AND 1024),
                    CHECK (
                        length(revocation_envelope_json)
                        BETWEEN 2 AND 1048576
                    ),
                    CHECK (
                        length(revocation_payload_json)
                        BETWEEN 2 AND 1048576
                    )
                );

            CREATE TABLE IF NOT EXISTS policy_activation_attempts (
                activation_attempt_id TEXT PRIMARY KEY,
                readiness_envelope_digest TEXT NOT NULL,
                readiness_payload_digest TEXT NOT NULL UNIQUE,
                readiness_core_digest TEXT NOT NULL,
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                compiler_analysis_payload_digest TEXT NOT NULL,
                approval_context_digest TEXT NOT NULL,
                approval_mode TEXT NOT NULL,
                required_approval_quorum BIGINT NOT NULL,
                expansion_cells_digest TEXT NOT NULL,
                publication_revision BIGINT NOT NULL,
                expected_high_water_digest TEXT NOT NULL,
                approval_id TEXT NOT NULL UNIQUE
                    REFERENCES policy_activation_approvals(approval_id)
                    ON DELETE RESTRICT,
                canary_id TEXT NOT NULL,
                artifact_envelope_digest TEXT NOT NULL,
                artifact_payload_digest TEXT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                candidate_policy_sequence BIGINT NOT NULL,
                candidate_rollback_epoch BIGINT NOT NULL,
                predecessor_policy_hash TEXT NOT NULL,
                expected_active_policy_sequence BIGINT NOT NULL,
                expected_active_rollback_epoch BIGINT NOT NULL,
                activation_mode TEXT NOT NULL,
                rollback_authorization_digest TEXT,
                activation_intent_digest TEXT NOT NULL,
                publication_intent_digest TEXT NOT NULL UNIQUE,
                activation_request_envelope_digest TEXT NOT NULL UNIQUE,
                activation_request_payload_digest TEXT NOT NULL UNIQUE,
                activation_request_envelope_json TEXT NOT NULL,
                activation_request_payload_json TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                created_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                UNIQUE (
                    activation_attempt_id, readiness_payload_digest,
                    candidate_policy_hash, candidate_policy_sequence,
                    candidate_rollback_epoch
                ),
                FOREIGN KEY (
                    readiness_envelope_digest, readiness_payload_digest,
                    canary_id, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    candidate_policy_sequence, candidate_rollback_epoch,
                    predecessor_policy_hash
                ) REFERENCES policy_canary_readiness (
                    readiness_envelope_digest, readiness_payload_digest,
                    canary_id, artifact_envelope_digest,
                    artifact_payload_digest, candidate_policy_hash,
                    candidate_policy_sequence, candidate_rollback_epoch,
                    predecessor_policy_hash
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    approval_id, readiness_payload_digest,
                    activation_intent_digest, approval_context_digest
                ) REFERENCES policy_activation_approvals (
                    approval_id, readiness_payload_digest,
                    activation_intent_digest, approval_context_digest
                ) ON DELETE RESTRICT,
                CHECK (activation_mode IN ('forward', 'authorized_rollback')),
                CHECK (required_approval_quorum IN (1, 2)),
                CHECK (publication_revision > 0),
                CHECK (
                    (
                        activation_mode = 'forward'
                        AND rollback_authorization_digest IS NULL
                        AND candidate_policy_sequence >
                            expected_active_policy_sequence
                        AND candidate_rollback_epoch =
                            expected_active_rollback_epoch
                    )
                    OR (
                        activation_mode = 'authorized_rollback'
                        AND rollback_authorization_digest IS NOT NULL
                        AND candidate_rollback_epoch >
                            expected_active_rollback_epoch
                    )
                ),
                FOREIGN KEY (
                    rollback_authorization_digest
                ) REFERENCES policy_activation_rollback_authorities (
                    rollback_authorization_payload_digest
                ) ON DELETE RESTRICT,
                CHECK (candidate_policy_sequence > 0),
                CHECK (candidate_rollback_epoch > 0),
                CHECK (expected_active_policy_sequence > 0),
                CHECK (expected_active_rollback_epoch >= 0),
                CHECK (created_at_epoch_ns >= 0),
                CHECK (expires_at_epoch_ns > created_at_epoch_ns),
                CHECK (length(activation_attempt_id) BETWEEN 1 AND 256),
                CHECK (length(requested_by) BETWEEN 1 AND 1024),
                CHECK (
                    length(activation_request_envelope_json)
                        BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(activation_request_payload_json)
                        BETWEEN 2 AND 1048576
                ),
                CHECK (
                    rollback_authorization_digest IS NULL
                    OR (
                        length(rollback_authorization_digest) = 71
                        AND substr(
                            rollback_authorization_digest, 1, 7
                        ) = 'sha256:'
                        AND lower(rollback_authorization_digest) =
                            rollback_authorization_digest
                    )
                )
            );

            CREATE TABLE IF NOT EXISTS policy_activation_preparations (
                preparation_digest TEXT PRIMARY KEY,
                activation_attempt_id TEXT NOT NULL UNIQUE
                    REFERENCES policy_activation_attempts(
                        activation_attempt_id
                    ) ON DELETE RESTRICT,
                activation_intent_digest TEXT NOT NULL UNIQUE,
                publication_intent_digest TEXT NOT NULL UNIQUE,
                readiness_payload_digest TEXT NOT NULL UNIQUE,
                approval_id TEXT NOT NULL UNIQUE
                    REFERENCES policy_activation_approvals(approval_id)
                    ON DELETE RESTRICT,
                approval_consumption_digest TEXT NOT NULL UNIQUE,
                rollback_authorization_digest TEXT UNIQUE,
                expected_high_water_digest TEXT NOT NULL,
                predecessor_policy_hash TEXT NOT NULL,
                candidate_policy_hash TEXT NOT NULL,
                candidate_policy_sequence BIGINT NOT NULL,
                candidate_rollback_epoch BIGINT NOT NULL,
                prepared_canary_revision BIGINT NOT NULL,
                prepared_canary_state_digest TEXT NOT NULL,
                authority_snapshot_json TEXT NOT NULL,
                authority_snapshot_digest TEXT NOT NULL,
                preparation_input_json TEXT NOT NULL,
                preparation_input_digest TEXT NOT NULL UNIQUE,
                transition_manifest_json TEXT NOT NULL,
                transition_manifest_root_digest TEXT NOT NULL UNIQUE,
                transition_count BIGINT NOT NULL,
                prepared_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                UNIQUE (
                    preparation_digest, activation_attempt_id,
                    preparation_input_digest,
                    transition_manifest_root_digest
                ),
                UNIQUE (
                    activation_attempt_id, preparation_input_digest
                ),
                UNIQUE (
                    preparation_digest, activation_attempt_id
                ),
                CHECK (candidate_policy_sequence > 0),
                CHECK (candidate_rollback_epoch > 0),
                CHECK (prepared_canary_revision > 0),
                CHECK (transition_count = 7),
                CHECK (prepared_at_epoch_ns >= 0),
                CHECK (expires_at_epoch_ns > prepared_at_epoch_ns),
                CHECK (
                    length(authority_snapshot_json)
                    BETWEEN 2 AND 4194304
                ),
                CHECK (
                    length(preparation_input_json)
                    BETWEEN 2 AND 8388608
                ),
                CHECK (
                    length(transition_manifest_json)
                    BETWEEN 2 AND 4194304
                )
            );

            CREATE TABLE IF NOT EXISTS
                policy_activation_prepared_transitions (
                    preparation_digest TEXT NOT NULL
                        REFERENCES policy_activation_preparations(
                            preparation_digest
                        ) ON DELETE RESTRICT,
                    transition_ordinal BIGINT NOT NULL,
                    transition_purpose TEXT NOT NULL,
                    transition_digest TEXT NOT NULL UNIQUE,
                    outbox_id TEXT NOT NULL UNIQUE,
                    outbox_event_digest TEXT NOT NULL,
                    event_payload_digest TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    entity_kind TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    entity_revision BIGINT NOT NULL,
                    state_digest TEXT NOT NULL,
                    previous_state_digest TEXT,
                    PRIMARY KEY (
                        preparation_digest, transition_ordinal
                    ),
                    UNIQUE (
                        preparation_digest, transition_purpose
                    ),
                    FOREIGN KEY (
                        transition_digest, entity_kind, entity_id,
                        entity_revision, state_digest,
                        previous_state_digest, event_type
                    ) REFERENCES policy_authority_transition_audits (
                        transition_digest, entity_kind, entity_id,
                        entity_revision, state_digest,
                        previous_state_digest, event_type
                    ) ON DELETE RESTRICT,
                    FOREIGN KEY (outbox_id, outbox_event_digest)
                        REFERENCES metadata_audit_outbox(id, event_digest)
                        ON DELETE RESTRICT,
                    CHECK (transition_ordinal > 0),
                    CHECK (entity_revision > 0),
                    CHECK (
                        transition_purpose IN (
                            'activation_prepared',
                            'canary_activating',
                            'activation_approved',
                            'activation_publishing',
                            'publication_committed',
                            'activation_committed',
                            'canary_active'
                        )
                    )
                );

            CREATE TABLE IF NOT EXISTS policy_activation_finalizations (
                preparation_digest TEXT PRIMARY KEY
                    REFERENCES policy_activation_preparations(
                        preparation_digest
                    ) ON DELETE RESTRICT,
                activation_attempt_id TEXT NOT NULL UNIQUE,
                preparation_input_digest TEXT NOT NULL,
                inclusion_identity_set_json TEXT NOT NULL,
                inclusion_identity_set_digest TEXT NOT NULL UNIQUE,
                publication_receipt_payload_digest TEXT NOT NULL UNIQUE,
                high_water_after_digest TEXT NOT NULL UNIQUE,
                finalized_authority_snapshot_json TEXT NOT NULL,
                finalized_authority_snapshot_digest TEXT NOT NULL UNIQUE,
                finalization_digest TEXT NOT NULL UNIQUE,
                finalized_at_epoch_ns BIGINT NOT NULL,
                FOREIGN KEY (
                    activation_attempt_id, preparation_input_digest
                ) REFERENCES policy_activation_preparations (
                    activation_attempt_id, preparation_input_digest
                ) ON DELETE RESTRICT,
                CHECK (finalized_at_epoch_ns >= 0),
                CHECK (
                    length(inclusion_identity_set_json)
                    BETWEEN 2 AND 4194304
                ),
                CHECK (
                    length(finalized_authority_snapshot_json)
                    BETWEEN 2 AND 4194304
                )
            );

            CREATE TABLE IF NOT EXISTS policy_activation_aborts (
                preparation_digest TEXT PRIMARY KEY
                    REFERENCES policy_activation_preparations(
                        preparation_digest
                    ) ON DELETE RESTRICT,
                activation_attempt_id TEXT NOT NULL UNIQUE,
                abort_reason TEXT NOT NULL,
                abort_digest TEXT NOT NULL UNIQUE,
                abort_transition_digest TEXT NOT NULL UNIQUE
                    REFERENCES policy_authority_transition_audits(
                        transition_digest
                    ) ON DELETE RESTRICT,
                aborted_by TEXT NOT NULL,
                aborted_at_epoch_ns BIGINT NOT NULL,
                FOREIGN KEY (
                    preparation_digest, activation_attempt_id
                ) REFERENCES policy_activation_preparations (
                    preparation_digest, activation_attempt_id
                ) ON DELETE RESTRICT,
                CHECK (
                    abort_reason IN (
                        'expired', 'predecessor_conflict',
                        'approval_revoked', 'trust_revoked',
                        'operator_cancelled'
                    )
                ),
                CHECK (length(aborted_by) BETWEEN 1 AND 1024),
                CHECK (aborted_at_epoch_ns >= 0)
            );

            CREATE TABLE IF NOT EXISTS policy_activation_publication_receipts (
                publication_receipt_envelope_digest TEXT PRIMARY KEY,
                publication_receipt_payload_digest TEXT NOT NULL UNIQUE,
                activation_attempt_id TEXT NOT NULL UNIQUE,
                readiness_payload_digest TEXT NOT NULL,
                readiness_core_digest TEXT NOT NULL,
                assignment_envelope_digest TEXT NOT NULL,
                assignment_payload_digest TEXT NOT NULL,
                compiler_analysis_payload_digest TEXT NOT NULL,
                approval_id TEXT NOT NULL
                    REFERENCES policy_activation_approvals(approval_id)
                    ON DELETE RESTRICT,
                approval_context_digest TEXT NOT NULL,
                approval_mode TEXT NOT NULL,
                required_approval_quorum BIGINT NOT NULL,
                expansion_cells_digest TEXT NOT NULL,
                activation_mode TEXT NOT NULL,
                rollback_authorization_payload_digest TEXT,
                publication_revision BIGINT NOT NULL,
                publication_intent_digest TEXT NOT NULL UNIQUE,
                committed_activation_revision BIGINT NOT NULL,
                committed_activation_state_digest TEXT NOT NULL UNIQUE,
                expected_canary_activating_state_digest TEXT NOT NULL,
                expected_canary_active_state_digest TEXT NOT NULL,
                policy_publication_hash TEXT NOT NULL
                    ,
                publication_status TEXT NOT NULL DEFAULT 'committed',
                scope TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                committed_policy_sequence BIGINT NOT NULL,
                committed_rollback_epoch BIGINT NOT NULL,
                committed_policy_hash TEXT NOT NULL,
                previous_policy_hash TEXT NOT NULL,
                high_water_before_digest TEXT NOT NULL,
                high_water_after_digest TEXT NOT NULL UNIQUE,
                publication_receipt_envelope_json TEXT NOT NULL,
                publication_receipt_payload_json TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'publication_receipt',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                publisher_id TEXT NOT NULL,
                committed_at_epoch_ns BIGINT NOT NULL,
                created_transition_digest TEXT NOT NULL UNIQUE
                    REFERENCES policy_authority_transition_audits(transition_digest)
                    ON DELETE RESTRICT,
                UNIQUE (
                    publication_receipt_envelope_digest,
                    publication_receipt_payload_digest,
                    activation_attempt_id
                ),
                FOREIGN KEY (
                    activation_attempt_id, readiness_payload_digest,
                    committed_policy_hash, committed_policy_sequence,
                    committed_rollback_epoch
                ) REFERENCES policy_activation_attempts (
                    activation_attempt_id, readiness_payload_digest,
                    candidate_policy_hash, candidate_policy_sequence,
                    candidate_rollback_epoch
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    policy_publication_hash, scope, policy_id,
                    committed_policy_sequence, committed_rollback_epoch,
                    previous_policy_hash, publication_status
                ) REFERENCES policy_publications (
                    policy_hash, scope, policy_id, sequence, rollback_epoch,
                    previous_policy_hash, status
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) REFERENCES policy_authority_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (scope = 'active'),
                CHECK (publication_status = 'committed'),
                CHECK (policy_publication_hash = committed_policy_hash),
                CHECK (required_approval_quorum IN (1, 2)),
                CHECK (activation_mode IN ('forward', 'authorized_rollback')),
                CHECK (
                    (activation_mode = 'forward'
                        AND rollback_authorization_payload_digest IS NULL)
                    OR
                    (activation_mode = 'authorized_rollback'
                        AND rollback_authorization_payload_digest IS NOT NULL)
                ),
                CHECK (publication_revision > 0),
                CHECK (evidence_kind = 'publication_receipt'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (committed_at_epoch_ns >= 0),
                CHECK (length(publisher_id) BETWEEN 1 AND 1024),
                CHECK (
                    length(publication_receipt_envelope_json)
                        BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(publication_receipt_payload_json)
                        BETWEEN 2 AND 1048576
                ),
                CHECK (length(signing_key_id) BETWEEN 1 AND 1024),
                CHECK (length(signature) BETWEEN 1 AND 4096)
            );

            CREATE TABLE IF NOT EXISTS policy_activation_approval_consumptions (
                approval_id TEXT PRIMARY KEY
                    REFERENCES policy_activation_approvals(approval_id)
                    ON DELETE RESTRICT,
                activation_attempt_id TEXT NOT NULL UNIQUE
                    REFERENCES policy_activation_attempts(activation_attempt_id)
                    ON DELETE RESTRICT,
                consumption_digest TEXT NOT NULL UNIQUE,
                consumed_by TEXT NOT NULL,
                consumed_at TEXT NOT NULL,
                member_count BIGINT NOT NULL,
                UNIQUE (
                    approval_id, activation_attempt_id, consumption_digest
                ),
                CHECK (member_count IN (1, 2)),
                CHECK (length(consumed_by) BETWEEN 1 AND 1024),
                CHECK (
                    length(consumption_digest) = 71
                    AND substr(consumption_digest, 1, 7) = 'sha256:'
                    AND lower(consumption_digest) = consumption_digest
                )
            );

            CREATE TABLE IF NOT EXISTS policy_activation_rollback_consumptions (
                rollback_authorization_payload_digest TEXT PRIMARY KEY,
                rollback_authorization_envelope_digest TEXT NOT NULL UNIQUE,
                activation_attempt_id TEXT NOT NULL UNIQUE
                    REFERENCES policy_activation_attempts(
                        activation_attempt_id
                    ) ON DELETE RESTRICT,
                readiness_payload_digest TEXT NOT NULL,
                approval_context_digest TEXT NOT NULL,
                webauthn_challenge_context_digest TEXT NOT NULL,
                expected_high_water_digest TEXT NOT NULL,
                publication_revision BIGINT NOT NULL,
                consumed_by TEXT NOT NULL,
                consumed_at_epoch_ns BIGINT NOT NULL,
                consumption_digest TEXT NOT NULL UNIQUE,
                FOREIGN KEY (
                    rollback_authorization_envelope_digest,
                    rollback_authorization_payload_digest
                ) REFERENCES policy_activation_rollback_authorities (
                    rollback_authorization_envelope_digest,
                    rollback_authorization_payload_digest
                ) ON DELETE RESTRICT,
                CHECK (publication_revision > 0),
                CHECK (consumed_at_epoch_ns >= 0),
                CHECK (length(consumed_by) BETWEEN 1 AND 1024)
            );

            CREATE TABLE IF NOT EXISTS policy_activation_revisions (
                activation_attempt_id TEXT NOT NULL
                    REFERENCES policy_activation_attempts(activation_attempt_id)
                    ON DELETE RESTRICT,
                revision BIGINT NOT NULL,
                status TEXT NOT NULL,
                previous_revision BIGINT,
                previous_status TEXT,
                previous_state_digest TEXT,
                approval_id TEXT,
                approval_consumption_digest TEXT,
                publication_intent_digest TEXT,
                uncertainty_digest TEXT,
                state_envelope_json TEXT NOT NULL,
                state_payload_json TEXT NOT NULL,
                state_digest TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                evidence_kind TEXT NOT NULL DEFAULT 'activation_state',
                record_binding_digest TEXT NOT NULL UNIQUE,
                verification_receipt_digest TEXT NOT NULL UNIQUE,
                created_at_epoch_ns BIGINT NOT NULL,
                approved_at_epoch_ns BIGINT,
                published_at_epoch_ns BIGINT,
                terminal_from_status TEXT,
                terminal_at_epoch_ns BIGINT,
                transition_digest TEXT NOT NULL UNIQUE,
                transition_entity_kind TEXT NOT NULL DEFAULT 'activation',
                transition_event_type TEXT NOT NULL,
                PRIMARY KEY (activation_attempt_id, revision),
                UNIQUE (
                    activation_attempt_id, revision, state_digest, status
                ),
                FOREIGN KEY (
                    activation_attempt_id, previous_revision,
                    previous_state_digest, previous_status
                ) REFERENCES policy_activation_revisions (
                    activation_attempt_id, revision, state_digest, status
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    approval_id, activation_attempt_id,
                    approval_consumption_digest
                ) REFERENCES policy_activation_approval_consumptions (
                    approval_id, activation_attempt_id, consumption_digest
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    transition_digest, transition_entity_kind,
                    activation_attempt_id, revision, state_digest,
                    previous_state_digest, transition_event_type
                ) REFERENCES policy_authority_transition_audits (
                    transition_digest, entity_kind, entity_id,
                    entity_revision, state_digest, previous_state_digest,
                    event_type
                ) ON DELETE RESTRICT,
                FOREIGN KEY (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) REFERENCES policy_authority_evidence_verifications (
                    verification_receipt_digest, evidence_kind,
                    signing_key_id, signature_digest, record_binding_digest
                ) ON DELETE RESTRICT,
                CHECK (
                    status IN (
                        'prepared', 'approved', 'publishing', 'committed',
                        'verifying', 'indeterminate', 'completed', 'denied',
                        'failed', 'expired', 'cancelled', 'superseded'
                    )
                ),
                CHECK (evidence_kind = 'activation_state'),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (
                    (
                        revision = 1
                        AND status = 'prepared'
                        AND previous_revision IS NULL
                        AND previous_status IS NULL
                        AND previous_state_digest IS NULL
                    )
                    OR (
                        revision > 1
                        AND previous_revision = revision - 1
                        AND previous_status IS NOT NULL
                        AND previous_state_digest IS NOT NULL
                    )
                ),
                CHECK (
                    revision = 1
                    OR (previous_status = 'prepared' AND status IN (
                        'approved', 'denied', 'expired', 'cancelled',
                        'superseded'
                    ))
                    OR (previous_status = 'approved' AND status IN (
                        'publishing', 'failed', 'expired', 'cancelled',
                        'superseded'
                    ))
                    OR (previous_status = 'publishing' AND status IN (
                        'committed', 'indeterminate', 'failed'
                    ))
                    OR (previous_status = 'committed' AND status IN (
                        'verifying', 'completed', 'indeterminate', 'failed'
                    ))
                    OR (previous_status = 'verifying' AND status IN (
                        'completed', 'indeterminate', 'failed'
                    ))
                ),
                CHECK (
                    (
                        approval_id IS NULL
                        AND approval_consumption_digest IS NULL
                        AND approved_at_epoch_ns IS NULL
                    )
                    OR (
                        approval_id IS NOT NULL
                        AND approval_consumption_digest IS NOT NULL
                        AND approved_at_epoch_ns IS NOT NULL
                    )
                ),
                CHECK (
                    status IN (
                        'prepared', 'denied', 'expired', 'cancelled',
                        'superseded'
                    )
                    OR approval_consumption_digest IS NOT NULL
                ),
                CHECK (
                    (
                        publication_intent_digest IS NULL
                        AND published_at_epoch_ns IS NULL
                    )
                    OR (
                        publication_intent_digest IS NOT NULL
                        AND published_at_epoch_ns IS NOT NULL
                    )
                ),
                CHECK (
                    status NOT IN ('committed', 'verifying', 'completed')
                    OR publication_intent_digest IS NOT NULL
                ),
                CHECK (
                    (status = 'indeterminate' AND uncertainty_digest IS NOT NULL)
                    OR (status <> 'indeterminate' AND uncertainty_digest IS NULL)
                ),
                CHECK (created_at_epoch_ns >= 0),
                CHECK (
                    approved_at_epoch_ns IS NULL
                    OR approved_at_epoch_ns >= created_at_epoch_ns
                ),
                CHECK (
                    published_at_epoch_ns IS NULL
                    OR (
                        approved_at_epoch_ns IS NOT NULL
                        AND published_at_epoch_ns >= approved_at_epoch_ns
                    )
                ),
                CHECK (
                    (
                        status IN (
                            'completed', 'indeterminate', 'denied', 'failed',
                            'expired', 'cancelled', 'superseded'
                        )
                        AND terminal_from_status = previous_status
                        AND terminal_at_epoch_ns IS NOT NULL
                        AND terminal_at_epoch_ns >= created_at_epoch_ns
                    )
                    OR (
                        status NOT IN (
                            'completed', 'indeterminate', 'denied', 'failed',
                            'expired', 'cancelled', 'superseded'
                        )
                        AND terminal_from_status IS NULL
                        AND terminal_at_epoch_ns IS NULL
                    )
                ),
                CHECK (transition_entity_kind = 'activation'),
                CHECK (length(state_envelope_json) BETWEEN 2 AND 1048576),
                CHECK (length(state_payload_json) BETWEEN 2 AND 1048576),
                CHECK (length(signing_key_id) BETWEEN 1 AND 1024),
                CHECK (length(signature) BETWEEN 1 AND 4096)
            );

            CREATE INDEX IF NOT EXISTS policy_activation_revisions_predecessor
                ON policy_activation_revisions (
                    activation_attempt_id, previous_revision,
                    previous_state_digest
                );

            CREATE TABLE IF NOT EXISTS policy_activation_heads (
                activation_attempt_id TEXT PRIMARY KEY
                    REFERENCES policy_activation_attempts(activation_attempt_id)
                    ON DELETE RESTRICT,
                head_revision BIGINT NOT NULL,
                head_state_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                unresolved_indeterminate BIGINT NOT NULL DEFAULT 0,
                updated_at_epoch_ns BIGINT NOT NULL,
                FOREIGN KEY (
                    activation_attempt_id, head_revision,
                    head_state_digest, status
                ) REFERENCES policy_activation_revisions (
                    activation_attempt_id, revision, state_digest, status
                ) ON DELETE RESTRICT,
                CHECK (unresolved_indeterminate IN (0, 1)),
                CHECK (
                    (status = 'indeterminate' AND unresolved_indeterminate = 1)
                    OR (status <> 'indeterminate' AND unresolved_indeterminate = 0)
                ),
                CHECK (head_revision > 0),
                CHECK (updated_at_epoch_ns >= 0)
            );

            CREATE TABLE IF NOT EXISTS
                policy_activation_finalized_exports (
                activation_attempt_id TEXT PRIMARY KEY
                    REFERENCES policy_activation_attempts(
                        activation_attempt_id
                    ) ON DELETE RESTRICT,
                preparation_digest TEXT NOT NULL UNIQUE
                    REFERENCES policy_activation_finalizations(
                        preparation_digest
                    ) ON DELETE RESTRICT,
                identity_json TEXT NOT NULL,
                identity_digest TEXT NOT NULL UNIQUE,
                manifest_json TEXT NOT NULL,
                manifest_root_digest TEXT NOT NULL UNIQUE,
                rows_json TEXT NOT NULL,
                rows_digest TEXT NOT NULL UNIQUE,
                row_identity_root_digest TEXT NOT NULL UNIQUE,
                section_count BIGINT NOT NULL,
                total_row_count BIGINT NOT NULL,
                total_canonical_bytes BIGINT NOT NULL,
                terminal_section_ordinal BIGINT NOT NULL,
                terminal_row_ordinal BIGINT NOT NULL,
                finalized_at_epoch_ns BIGINT NOT NULL,
                source_revision TEXT NOT NULL,
                CHECK (section_count > 0),
                CHECK (total_row_count >= 0),
                CHECK (total_canonical_bytes >= 0),
                CHECK (terminal_section_ordinal = section_count),
                CHECK (terminal_row_ordinal = total_row_count),
                CHECK (finalized_at_epoch_ns >= 0),
                CHECK (
                    source_revision =
                        'serverware.policyCandidateAuthoritySource/2026-07-30.351'
                ),
                CHECK (length(identity_json) BETWEEN 2 AND 4194304),
                CHECK (length(manifest_json) BETWEEN 2 AND 4194304),
                CHECK (length(rows_json) BETWEEN 2 AND 67108864)
            );

            CREATE TABLE IF NOT EXISTS policy_activation_export_issuances (
                export_id TEXT PRIMARY KEY,
                export_revision BIGINT NOT NULL,
                activation_attempt_id TEXT NOT NULL
                    REFERENCES policy_activation_attempts(
                        activation_attempt_id
                    ) ON DELETE RESTRICT,
                canary_id TEXT NOT NULL,
                assignment_envelope_digest TEXT NOT NULL,
                identity_json TEXT NOT NULL,
                identity_digest TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                manifest_root_digest TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                snapshot_digest TEXT NOT NULL UNIQUE,
                section_count BIGINT NOT NULL,
                total_row_count BIGINT NOT NULL,
                total_canonical_bytes BIGINT NOT NULL,
                page_count BIGINT NOT NULL,
                page_chain_root_digest TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                prepared_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                UNIQUE (export_id, export_revision),
                UNIQUE (
                    export_id, export_revision, activation_attempt_id,
                    assignment_envelope_digest, identity_digest,
                    manifest_root_digest, snapshot_digest,
                    page_chain_root_digest
                ),
                UNIQUE (
                    export_id, export_revision,
                    assignment_envelope_digest
                ),
                UNIQUE (
                    export_id, export_revision, snapshot_digest,
                    page_chain_root_digest
                ),
                UNIQUE (activation_attempt_id),
                CHECK (export_revision = 1),
                CHECK (section_count > 0),
                CHECK (total_row_count >= 0),
                CHECK (total_canonical_bytes >= 0),
                CHECK (page_count > 0),
                CHECK (
                    source_revision =
                        'serverware.policyCandidateAuthoritySource/2026-07-30.351'
                ),
                CHECK (expires_at_epoch_ns > prepared_at_epoch_ns),
                CHECK (length(identity_json) BETWEEN 2 AND 4194304),
                CHECK (length(manifest_json) BETWEEN 2 AND 4194304),
                CHECK (length(snapshot_json) BETWEEN 2 AND 4194304)
            );

            CREATE TABLE IF NOT EXISTS policy_activation_export_pages (
                export_id TEXT NOT NULL,
                export_revision BIGINT NOT NULL,
                page_ordinal BIGINT NOT NULL,
                section_name TEXT NOT NULL,
                section_page_ordinal BIGINT NOT NULL,
                predecessor_page_digest TEXT,
                successor_page_digest TEXT,
                page_material_json TEXT NOT NULL,
                page_digest TEXT NOT NULL UNIQUE,
                rows_json TEXT NOT NULL,
                rows_digest TEXT NOT NULL,
                row_count BIGINT NOT NULL,
                canonical_bytes BIGINT NOT NULL,
                cumulative_row_count BIGINT NOT NULL,
                cumulative_root_digest TEXT NOT NULL,
                section_root_digest TEXT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                PRIMARY KEY (export_id, page_ordinal),
                UNIQUE (
                    export_id, section_name, section_page_ordinal
                ),
                UNIQUE (
                    export_id, page_ordinal, page_digest
                ),
                FOREIGN KEY (
                    export_id, export_revision
                ) REFERENCES policy_activation_export_issuances (
                    export_id, export_revision
                ) ON DELETE RESTRICT,
                CHECK (export_revision = 1),
                CHECK (page_ordinal > 0),
                CHECK (section_page_ordinal > 0),
                CHECK (row_count >= 0),
                CHECK (canonical_bytes >= 0),
                CHECK (cumulative_row_count >= row_count),
                CHECK (length(section_name) BETWEEN 1 AND 128),
                CHECK (length(page_material_json) BETWEEN 2 AND 4194304),
                CHECK (length(rows_json) BETWEEN 2 AND 4194304)
            );

            CREATE TABLE IF NOT EXISTS
                policy_activation_export_attestations (
                    export_id TEXT PRIMARY KEY,
                    export_revision BIGINT NOT NULL,
                    assignment_envelope_digest TEXT NOT NULL,
                    member_ordinal BIGINT NOT NULL,
                    canary_id TEXT NOT NULL,
                    fleet_id TEXT NOT NULL,
                    membership_revision BIGINT NOT NULL,
                    instance_id TEXT NOT NULL,
                    boot_id TEXT NOT NULL,
                    issuance_envelope_json TEXT NOT NULL,
                    issuance_envelope_digest TEXT NOT NULL UNIQUE,
                    issuance_payload_json TEXT NOT NULL UNIQUE,
                    issuance_payload_digest TEXT NOT NULL UNIQUE,
                    signature_algorithm TEXT NOT NULL,
                    signing_key_id TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    signature_digest TEXT NOT NULL UNIQUE,
                    evidence_kind TEXT NOT NULL
                        DEFAULT 'activation_export_issuance',
                    record_binding_digest TEXT NOT NULL UNIQUE,
                    verification_receipt_digest TEXT NOT NULL UNIQUE,
                    issued_at_epoch_ns BIGINT NOT NULL,
                    expires_at_epoch_ns BIGINT NOT NULL,
                    FOREIGN KEY (
                        export_id, export_revision,
                        assignment_envelope_digest
                    ) REFERENCES policy_activation_export_issuances (
                        export_id, export_revision,
                        assignment_envelope_digest
                    ) ON DELETE RESTRICT,
                    FOREIGN KEY (
                        verification_receipt_digest, evidence_kind,
                        assignment_envelope_digest, member_ordinal,
                        signature_digest, record_binding_digest
                    ) REFERENCES policy_runtime_evidence_verifications (
                        verification_receipt_digest, evidence_kind,
                        assignment_envelope_digest, member_ordinal,
                        signature_digest, record_binding_digest
                    ) ON DELETE RESTRICT,
                    CHECK (
                        evidence_kind = 'activation_export_issuance'
                    ),
                    CHECK (signature_algorithm = 'Ed25519'),
                    CHECK (export_revision = 1),
                    CHECK (member_ordinal > 0)
                );

            CREATE TABLE IF NOT EXISTS
                policy_activation_export_page_attestations (
                    export_id TEXT NOT NULL,
                    page_ordinal BIGINT NOT NULL,
                    page_digest TEXT NOT NULL UNIQUE,
                    assignment_envelope_digest TEXT NOT NULL,
                    member_ordinal BIGINT NOT NULL,
                    canary_id TEXT NOT NULL,
                    fleet_id TEXT NOT NULL,
                    membership_revision BIGINT NOT NULL,
                    instance_id TEXT NOT NULL,
                    boot_id TEXT NOT NULL,
                    page_envelope_json TEXT NOT NULL,
                    page_envelope_digest TEXT NOT NULL UNIQUE,
                    page_payload_json TEXT NOT NULL UNIQUE,
                    page_payload_digest TEXT NOT NULL UNIQUE,
                    signature_algorithm TEXT NOT NULL,
                    signing_key_id TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    signature_digest TEXT NOT NULL UNIQUE,
                    evidence_kind TEXT NOT NULL
                        DEFAULT 'activation_export_page',
                    record_binding_digest TEXT NOT NULL UNIQUE,
                    verification_receipt_digest TEXT NOT NULL UNIQUE,
                    issued_at_epoch_ns BIGINT NOT NULL,
                    expires_at_epoch_ns BIGINT NOT NULL,
                    PRIMARY KEY (export_id, page_ordinal),
                    FOREIGN KEY (
                        export_id, page_ordinal, page_digest
                    ) REFERENCES policy_activation_export_pages (
                        export_id, page_ordinal, page_digest
                    ) ON DELETE RESTRICT,
                    FOREIGN KEY (
                        verification_receipt_digest, evidence_kind,
                        assignment_envelope_digest, member_ordinal,
                        signature_digest, record_binding_digest
                    ) REFERENCES policy_runtime_evidence_verifications (
                        verification_receipt_digest, evidence_kind,
                        assignment_envelope_digest, member_ordinal,
                        signature_digest, record_binding_digest
                    ) ON DELETE RESTRICT,
                    CHECK (evidence_kind = 'activation_export_page'),
                    CHECK (signature_algorithm = 'Ed25519'),
                    CHECK (page_ordinal > 0),
                    CHECK (member_ordinal > 0)
                );

            CREATE TABLE IF NOT EXISTS
                policy_activation_export_authorizations (
                    export_id TEXT NOT NULL,
                    authorization_revision BIGINT NOT NULL,
                    export_revision BIGINT NOT NULL,
                    snapshot_digest TEXT NOT NULL,
                    page_chain_root_digest TEXT NOT NULL,
                    predecessor_authorization_digest TEXT,
                    authorization_material_json TEXT NOT NULL,
                    authorization_digest TEXT NOT NULL UNIQUE,
                    issuance_verification_receipt_digest TEXT NOT NULL,
                    page_verification_receipts_root_digest TEXT NOT NULL,
                    authorized_at_epoch_ns BIGINT NOT NULL,
                    expires_at_epoch_ns BIGINT NOT NULL,
                    source_revision TEXT NOT NULL,
                    PRIMARY KEY (export_id, authorization_revision),
                    UNIQUE (
                        export_id, authorization_revision,
                        authorization_digest, expires_at_epoch_ns
                    ),
                    FOREIGN KEY (
                        export_id, export_revision, snapshot_digest,
                        page_chain_root_digest
                    ) REFERENCES policy_activation_export_issuances (
                        export_id, export_revision, snapshot_digest,
                        page_chain_root_digest
                    ) ON DELETE RESTRICT,
                    FOREIGN KEY (
                        issuance_verification_receipt_digest
                    ) REFERENCES policy_runtime_evidence_verifications (
                        verification_receipt_digest
                    ) ON DELETE RESTRICT,
                    CHECK (authorization_revision > 0),
                    CHECK (export_revision = 1),
                    CHECK (
                        (
                            authorization_revision = 1
                            AND predecessor_authorization_digest IS NULL
                        )
                        OR (
                            authorization_revision > 1
                            AND predecessor_authorization_digest IS NOT NULL
                        )
                    ),
                    CHECK (
                        expires_at_epoch_ns > authorized_at_epoch_ns
                    ),
                    CHECK (
                        source_revision =
                            'serverware.policyCandidateAuthoritySource/2026-07-30.351'
                    ),
                    CHECK (
                        length(authorization_material_json)
                        BETWEEN 2 AND 4194304
                    )
                );

            CREATE TABLE IF NOT EXISTS
                policy_activation_export_authorization_receipts (
                    export_id TEXT NOT NULL,
                    authorization_revision BIGINT NOT NULL,
                    page_ordinal BIGINT NOT NULL,
                    verification_receipt_digest TEXT NOT NULL,
                    issued_at_epoch_ns BIGINT NOT NULL,
                    expires_at_epoch_ns BIGINT NOT NULL,
                    PRIMARY KEY (
                        export_id, authorization_revision, page_ordinal
                    ),
                    UNIQUE (
                        export_id, authorization_revision,
                        verification_receipt_digest
                    ),
                    FOREIGN KEY (
                        export_id, authorization_revision
                    ) REFERENCES policy_activation_export_authorizations (
                        export_id, authorization_revision
                    ) ON DELETE RESTRICT,
                    FOREIGN KEY (
                        verification_receipt_digest
                    ) REFERENCES policy_runtime_evidence_verifications (
                        verification_receipt_digest
                    ) ON DELETE RESTRICT,
                    CHECK (authorization_revision > 0),
                    CHECK (page_ordinal > 0),
                    CHECK (issued_at_epoch_ns >= 0),
                    CHECK (expires_at_epoch_ns > issued_at_epoch_ns)
                );

            CREATE TABLE IF NOT EXISTS
                policy_activation_export_authorization_heads (
                    export_id TEXT PRIMARY KEY,
                    authorization_revision BIGINT NOT NULL,
                    authorization_digest TEXT NOT NULL UNIQUE,
                    expires_at_epoch_ns BIGINT NOT NULL,
                    updated_at_epoch_ns BIGINT NOT NULL,
                    FOREIGN KEY (
                        export_id, authorization_revision,
                        authorization_digest, expires_at_epoch_ns
                    ) REFERENCES policy_activation_export_authorizations (
                        export_id, authorization_revision,
                        authorization_digest, expires_at_epoch_ns
                    ) ON DELETE RESTRICT,
                    CHECK (authorization_revision > 0),
                    CHECK (updated_at_epoch_ns >= 0)
                );

            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                id TEXT PRIMARY KEY,
                credential_id TEXT NOT NULL UNIQUE,
                user_id TEXT NOT NULL,
                label TEXT NOT NULL,
                public_key_cose TEXT NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                aaguid TEXT,
                authenticator_class TEXT NOT NULL DEFAULT 'unknown',
                attestation_fmt TEXT,
                attestation_trusted INTEGER NOT NULL DEFAULT 0,
                attestation_trust_path TEXT NOT NULL DEFAULT '[]',
                attestation_leaf_sha256 TEXT,
                attestation_root_sha256 TEXT,
                attestation_trust_bundle_digest TEXT,
                attestation_trust_bundle_sequence INTEGER,
                attestation_verified_at TEXT,
                transports TEXT NOT NULL DEFAULT '[]',
                dev_private_key_pem TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT,
                revoked_by TEXT,
                revocation_reason TEXT,
                revocation_source TEXT
            );

            CREATE TABLE IF NOT EXISTS oidc_browser_sessions (
                id TEXT PRIMARY KEY,
                token_digest TEXT NOT NULL UNIQUE,
                oidc_token_digest TEXT NOT NULL,
                user_id TEXT NOT NULL,
                roles_json TEXT NOT NULL,
                status TEXT NOT NULL,
                provider_expires_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                pending_expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                activated_at TEXT,
                revoked_at TEXT,
                bound_webauthn_credential_id TEXT
                    REFERENCES webauthn_credentials(id),
                activation_trust_bundle_digest TEXT,
                activation_trust_bundle_sequence BIGINT,
                activation_authenticator_class TEXT,
                revocation_reason TEXT,
                CHECK (
                    length(token_digest) = 71
                    AND substr(token_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(oidc_token_digest) = 71
                    AND substr(oidc_token_digest, 1, 7) = 'sha256:'
                ),
                CHECK (status IN ('pending_webauthn', 'active', 'revoked')),
                CHECK (length(roles_json) <= 4096),
                CHECK (
                    (status = 'pending_webauthn'
                        AND pending_expires_at IS NOT NULL
                        AND activated_at IS NULL
                        AND revoked_at IS NULL
                        AND bound_webauthn_credential_id IS NULL)
                    OR (status = 'active'
                        AND pending_expires_at IS NULL
                        AND activated_at IS NOT NULL
                        AND revoked_at IS NULL)
                    OR (status = 'revoked' AND revoked_at IS NOT NULL)
                )
            );

            CREATE INDEX IF NOT EXISTS oidc_browser_sessions_status_expiry
                ON oidc_browser_sessions (status, expires_at);

            CREATE INDEX IF NOT EXISTS oidc_browser_sessions_user_live
                ON oidc_browser_sessions (user_id, status, expires_at);

            CREATE INDEX IF NOT EXISTS oidc_browser_sessions_webauthn_binding
                ON oidc_browser_sessions (bound_webauthn_credential_id, status);

            CREATE TABLE IF NOT EXISTS oidc_session_activation_deliveries (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL UNIQUE
                    REFERENCES oidc_browser_sessions(id) ON DELETE CASCADE,
                old_token_digest TEXT NOT NULL UNIQUE,
                new_token_digest TEXT NOT NULL UNIQUE,
                assertion_digest TEXT NOT NULL UNIQUE,
                challenge_id TEXT NOT NULL UNIQUE,
                credential_record_id TEXT NOT NULL
                    REFERENCES webauthn_credentials(id),
                encrypted_active_token TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                CHECK (
                    length(old_token_digest) = 71
                    AND substr(old_token_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(new_token_digest) = 71
                    AND substr(new_token_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(assertion_digest) = 71
                    AND substr(assertion_digest, 1, 7) = 'sha256:'
                ),
                CHECK (length(encrypted_active_token) <= 4096)
            );

            CREATE INDEX IF NOT EXISTS oidc_activation_delivery_live
                ON oidc_session_activation_deliveries
                    (old_token_digest, assertion_digest, consumed_at, expires_at);

            CREATE INDEX IF NOT EXISTS oidc_activation_delivery_expiry
                ON oidc_session_activation_deliveries (expires_at, consumed_at);

            CREATE TABLE IF NOT EXISTS webauthn_challenges (
                id TEXT PRIMARY KEY,
                challenge TEXT NOT NULL UNIQUE,
                challenge_type TEXT NOT NULL,
                user_id TEXT NOT NULL,
                scope_key TEXT,
                approval_request_id TEXT,
                payload_json TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                retention_recovery_id TEXT,
                retention_recovery_row_digest TEXT,
                retention_jit_receipt_digest TEXT,
                retention_jit_row_digest TEXT,
                retention_activation_receipt_digest TEXT,
                retention_activation_row_digest TEXT,
                retention_reference_mask BIGINT NOT NULL DEFAULT 0,
                -- New-source ordering contract, never an adoption/backfill of
                -- historical custom IDs. Installation separately requires all
                -- challenge/reference source tables to be genuinely empty.
                CONSTRAINT webauthn_challenge_fresh_generated_id CHECK (
                    (length(id) = 36 AND id COLLATE "C" ~
                     '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') OR
                    (length(id) = 71 AND id COLLATE "C" ~ '^sha256:[0-9a-f]{64}$')),
                CHECK ((retention_recovery_id IS NULL) =
                       (retention_recovery_row_digest IS NULL)),
                CHECK ((retention_jit_receipt_digest IS NULL) =
                       (retention_jit_row_digest IS NULL)),
                CHECK ((retention_activation_receipt_digest IS NULL) =
                       (retention_activation_row_digest IS NULL)),
                CHECK (retention_reference_mask =
                    CASE WHEN retention_recovery_id IS NULL THEN 0 ELSE 1 END +
                    CASE WHEN retention_jit_receipt_digest IS NULL THEN 0 ELSE 2 END +
                    CASE WHEN retention_activation_receipt_digest IS NULL THEN 0 ELSE 4 END),
                CHECK (retention_recovery_row_digest IS NULL OR
                       retention_recovery_row_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (retention_jit_row_digest IS NULL OR
                       retention_jit_row_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (retention_activation_row_digest IS NULL OR
                       retention_activation_row_digest ~ '^sha256:[0-9a-f]{64}$')
            );

            CREATE TABLE IF NOT EXISTS jit_webauthn_assertion_receipts (
                assertion_receipt_digest TEXT PRIMARY KEY,
                approval_request_id TEXT NOT NULL
                    REFERENCES approval_requests(id) ON DELETE RESTRICT,
                approver_id TEXT NOT NULL,
                approver_policy_digest TEXT NOT NULL,
                decision TEXT NOT NULL,
                credential_record_id TEXT NOT NULL
                    REFERENCES webauthn_credentials(id) ON DELETE RESTRICT,
                credential_id TEXT NOT NULL,
                challenge_id TEXT NOT NULL UNIQUE
                    REFERENCES webauthn_challenges(id) ON DELETE RESTRICT,
                assertion_digest TEXT NOT NULL UNIQUE,
                assertion_json TEXT NOT NULL,
                client_data_json_digest TEXT NOT NULL UNIQUE,
                authenticator_data_digest TEXT NOT NULL UNIQUE,
                assertion_signature_digest TEXT NOT NULL UNIQUE,
                challenge_payload_digest TEXT NOT NULL,
                credential_binding_digest TEXT NOT NULL,
                rp_id TEXT NOT NULL,
                origin TEXT NOT NULL,
                authenticator_class TEXT NOT NULL,
                trust_bundle_digest TEXT,
                trust_bundle_sequence BIGINT,
                sign_count_before BIGINT NOT NULL,
                sign_count_after BIGINT NOT NULL,
                user_present BIGINT NOT NULL,
                user_verified BIGINT NOT NULL,
                attestation_trusted BIGINT NOT NULL,
                challenge_created_at TEXT NOT NULL,
                challenge_used_at TEXT NOT NULL,
                verified_at TEXT NOT NULL,
                verified_at_epoch_ns BIGINT NOT NULL,
                CHECK (sign_count_before >= 0),
                CHECK (sign_count_after >= 0),
                CHECK (
                    (sign_count_before = 0 AND sign_count_after = 0)
                    OR sign_count_after > sign_count_before
                ),
                CHECK (user_present = 1),
                CHECK (user_verified = 1),
                CHECK (attestation_trusted IN (0, 1)),
                CHECK (decision IN ('approve', 'deny')),
                CHECK (verified_at_epoch_ns >= 0),
                CHECK (length(assertion_json) BETWEEN 2 AND 1048576),
                CHECK (length(rp_id) BETWEEN 1 AND 253),
                CHECK (length(origin) BETWEEN 1 AND 2048)
            );

            CREATE TABLE IF NOT EXISTS approval_request_decisions (
                approval_request_id TEXT NOT NULL
                    REFERENCES approval_requests(id) ON DELETE RESTRICT,
                approver_id TEXT NOT NULL,
                approver_policy_digest TEXT NOT NULL,
                verified_assertion_receipt_digest TEXT NOT NULL UNIQUE
                    REFERENCES
                        policy_authority_webauthn_assertion_receipts(
                            assertion_receipt_digest
                        ) ON DELETE RESTRICT,
                authority_capability_id TEXT NOT NULL UNIQUE
                    REFERENCES policy_authority_writer_capabilities(
                        capability_id
                    ) ON DELETE RESTRICT,
                authority_request_digest TEXT NOT NULL UNIQUE,
                review_receipt_id TEXT
                    REFERENCES approval_review_receipts(id) ON DELETE RESTRICT,
                review_digest TEXT,
                require_review_receipt BIGINT NOT NULL DEFAULT 0,
                decision TEXT NOT NULL,
                decision_note TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY (approval_request_id, approver_id),
                CHECK (decision = 'approved'),
                CHECK (
                    approver_policy_digest ~
                        '^sha256:[0-9a-f]{64}$'
                ),
                CHECK (
                    authority_capability_id ~
                        '^sha256:[0-9a-f]{64}$'
                ),
                CHECK (
                    authority_request_digest ~
                        '^sha256:[0-9a-f]{64}$'
                ),
                CHECK (require_review_receipt IN (0, 1)),
                CHECK (
                    (
                        require_review_receipt = 0
                        AND review_receipt_id IS NULL
                        AND review_digest IS NULL
                    )
                    OR (
                        require_review_receipt = 1
                        AND review_receipt_id IS NOT NULL
                        AND review_digest IS NOT NULL
                    )
                )
            );

            CREATE TABLE IF NOT EXISTS policy_activation_webauthn_assertions (
                assertion_receipt_digest TEXT PRIMARY KEY,
                approval_id TEXT NOT NULL,
                control_plane_approval_id TEXT NOT NULL UNIQUE
                    REFERENCES control_plane_approvals(id) ON DELETE RESTRICT,
                approver_id TEXT NOT NULL,
                credential_record_id TEXT NOT NULL
                    REFERENCES webauthn_credentials(id) ON DELETE RESTRICT,
                challenge_id TEXT NOT NULL UNIQUE
                    REFERENCES webauthn_challenges(id) ON DELETE RESTRICT,
                readiness_payload_digest TEXT NOT NULL,
                activation_intent_digest TEXT NOT NULL,
                approval_context_digest TEXT NOT NULL,
                assertion_digest TEXT NOT NULL UNIQUE,
                assertion_json TEXT NOT NULL,
                client_data_digest TEXT NOT NULL UNIQUE,
                authenticator_data_digest TEXT NOT NULL UNIQUE,
                assertion_signature_digest TEXT NOT NULL UNIQUE,
                challenge_payload_digest TEXT NOT NULL,
                rp_id TEXT NOT NULL,
                origin TEXT NOT NULL,
                client_data_type TEXT NOT NULL,
                authenticator_class TEXT NOT NULL,
                trust_bundle_digest TEXT NOT NULL,
                trust_bundle_sequence BIGINT NOT NULL,
                sign_count BIGINT NOT NULL,
                user_present BIGINT NOT NULL,
                user_verified BIGINT NOT NULL,
                attestation_trusted BIGINT NOT NULL,
                control_plane_approval_snapshot_json TEXT NOT NULL,
                control_plane_approval_snapshot_digest TEXT NOT NULL,
                webauthn_challenge_snapshot_json TEXT NOT NULL,
                webauthn_challenge_snapshot_digest TEXT NOT NULL,
                webauthn_credential_snapshot_json TEXT NOT NULL,
                webauthn_credential_snapshot_digest TEXT NOT NULL,
                webauthn_credential_version_digest TEXT NOT NULL,
                webauthn_credential_public_key_digest TEXT NOT NULL,
                webauthn_trust_publication_snapshot_json TEXT NOT NULL,
                webauthn_trust_publication_snapshot_digest TEXT NOT NULL,
                challenge_created_at TEXT NOT NULL,
                challenge_used_at TEXT NOT NULL,
                assertion_issued_at TEXT NOT NULL,
                approval_approved_at TEXT NOT NULL,
                assertion_verified_at TEXT NOT NULL,
                verified_at_epoch_ns BIGINT NOT NULL,
                UNIQUE (
                    assertion_receipt_digest, approval_id,
                    control_plane_approval_id, approver_id,
                    credential_record_id, challenge_id, assertion_digest,
                    readiness_payload_digest,
                    activation_intent_digest,
                    approval_context_digest
                ),
                FOREIGN KEY (
                    approval_id, readiness_payload_digest,
                    activation_intent_digest,
                    approval_context_digest
                ) REFERENCES policy_activation_approvals (
                    approval_id, readiness_payload_digest,
                    activation_intent_digest,
                    approval_context_digest
                ) ON DELETE RESTRICT,
                CHECK (sign_count >= 0),
                CHECK (trust_bundle_sequence > 0),
                CHECK (user_present = 1),
                CHECK (user_verified = 1),
                CHECK (attestation_trusted = 1),
                CHECK (challenge_used_at >= challenge_created_at),
                CHECK (assertion_issued_at = challenge_used_at),
                CHECK (approval_approved_at >= challenge_created_at),
                CHECK (assertion_verified_at >= assertion_issued_at),
                CHECK (assertion_verified_at >= approval_approved_at),
                CHECK (
                    authenticator_class IN ('yubikey', 'hardware')
                ),
                CHECK (verified_at_epoch_ns >= 0),
                CHECK (length(rp_id) BETWEEN 1 AND 253),
                CHECK (length(origin) BETWEEN 1 AND 2048),
                CHECK (client_data_type = 'webauthn.get'),
                CHECK (length(assertion_json) BETWEEN 2 AND 1048576),
                CHECK (
                    length(control_plane_approval_snapshot_json)
                    BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(webauthn_challenge_snapshot_json)
                    BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(webauthn_credential_snapshot_json)
                    BETWEEN 2 AND 1048576
                ),
                CHECK (
                    length(webauthn_trust_publication_snapshot_json)
                    BETWEEN 2 AND 4194304
                ),
                CHECK (length(approver_id) BETWEEN 1 AND 1024),
                CHECK (
                    length(assertion_receipt_digest) = 71
                    AND substr(assertion_receipt_digest, 1, 7) = 'sha256:'
                    AND lower(assertion_receipt_digest) =
                        assertion_receipt_digest
                ),
                CHECK (
                    length(assertion_digest) = 71
                    AND substr(assertion_digest, 1, 7) = 'sha256:'
                    AND lower(assertion_digest) = assertion_digest
                ),
                CHECK (
                    length(challenge_payload_digest) = 71
                    AND substr(challenge_payload_digest, 1, 7) = 'sha256:'
                    AND lower(challenge_payload_digest) =
                        challenge_payload_digest
                )
            );

            CREATE TABLE IF NOT EXISTS policy_activation_approval_members (
                approval_id TEXT NOT NULL
                    REFERENCES policy_activation_approvals(approval_id)
                    ON DELETE RESTRICT,
                member_ordinal BIGINT NOT NULL,
                control_plane_approval_id TEXT NOT NULL UNIQUE
                    REFERENCES control_plane_approvals(id) ON DELETE RESTRICT,
                approver_id TEXT NOT NULL,
                approver_webauthn_credential_id TEXT NOT NULL,
                approval_evidence_digest TEXT NOT NULL UNIQUE,
                control_plane_request_digest TEXT NOT NULL,
                webauthn_assertion_receipt_digest TEXT NOT NULL UNIQUE,
                webauthn_assertion_digest TEXT NOT NULL UNIQUE,
                webauthn_challenge_id TEXT NOT NULL UNIQUE,
                readiness_payload_digest TEXT NOT NULL,
                activation_intent_digest TEXT NOT NULL,
                approval_context_digest TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (approval_id, member_ordinal),
                UNIQUE (approval_id, approver_id),
                UNIQUE (approval_id, approver_webauthn_credential_id),
                FOREIGN KEY (
                    webauthn_assertion_receipt_digest, approval_id,
                    control_plane_approval_id, approver_id,
                    approver_webauthn_credential_id, webauthn_challenge_id,
                    webauthn_assertion_digest, readiness_payload_digest,
                    activation_intent_digest,
                    approval_context_digest
                ) REFERENCES policy_activation_webauthn_assertions (
                    assertion_receipt_digest, approval_id,
                    control_plane_approval_id, approver_id,
                    credential_record_id, challenge_id, assertion_digest,
                    readiness_payload_digest,
                    activation_intent_digest,
                    approval_context_digest
                ) ON DELETE RESTRICT,
                CHECK (member_ordinal IN (1, 2)),
                CHECK (length(approver_id) BETWEEN 1 AND 1024),
                CHECK (
                    length(approval_evidence_digest) = 71
                    AND substr(approval_evidence_digest, 1, 7) = 'sha256:'
                    AND lower(approval_evidence_digest) =
                        approval_evidence_digest
                ),
                CHECK (
                    length(control_plane_request_digest) = 71
                    AND substr(control_plane_request_digest, 1, 7) = 'sha256:'
                    AND lower(control_plane_request_digest) =
                        control_plane_request_digest
                )
            );

            CREATE TABLE IF NOT EXISTS webauthn_recovery_root_state (
                signing_key_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                last_consumed_sequence BIGINT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (last_consumed_sequence >= 0),
                PRIMARY KEY (signing_key_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS webauthn_recovery_ceremonies (
                id TEXT PRIMARY KEY,
                nonce TEXT NOT NULL UNIQUE,
                user_id TEXT NOT NULL,
                oidc_session_id TEXT NOT NULL,
                pending_token_digest TEXT NOT NULL,
                oidc_token_digest TEXT NOT NULL,
                roles_json TEXT NOT NULL,
                identity_digest TEXT NOT NULL,
                session_expires_at TEXT NOT NULL,
                pending_expires_at TEXT NOT NULL,
                label TEXT NOT NULL,
                reason TEXT NOT NULL,
                challenge_id TEXT NOT NULL UNIQUE
                    REFERENCES webauthn_challenges(id),
                challenge_digest TEXT NOT NULL UNIQUE,
                credential_history_digest TEXT NOT NULL,
                credential_history_count BIGINT NOT NULL,
                active_credential_count BIGINT NOT NULL,
                trust_bundle_digest TEXT NOT NULL,
                trust_bundle_sequence BIGINT NOT NULL,
                trust_bundle_rollback_epoch BIGINT NOT NULL,
                trust_signing_key_id TEXT NOT NULL,
                auth_policy_digest TEXT NOT NULL,
                recovery_root_key_id TEXT NOT NULL,
                recovery_root_provider TEXT NOT NULL,
                recovery_audience TEXT NOT NULL,
                rp_id TEXT NOT NULL,
                origin TEXT NOT NULL,
                root_sequence BIGINT,
                status TEXT NOT NULL,
                candidate_json TEXT,
                candidate_digest TEXT UNIQUE,
                statement_json TEXT,
                statement_digest TEXT UNIQUE,
                authorization_json TEXT,
                authorization_digest TEXT UNIQUE,
                signature_digest TEXT UNIQUE,
                replacement_record_id TEXT UNIQUE
                    REFERENCES webauthn_credentials(id),
                created_at TEXT NOT NULL,
                prepared_at TEXT,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                invalidated_at TEXT,
                CHECK (
                    status IN (
                        'pending_candidate', 'prepared', 'consumed',
                        'expired', 'invalidated'
                    )
                ),
                CHECK (credential_history_count > 0),
                CHECK (active_credential_count = 0),
                CHECK (root_sequence IS NULL OR root_sequence > 0),
                CHECK (length(roles_json) <= 4096)
            );

            CREATE UNIQUE INDEX IF NOT EXISTS webauthn_recovery_one_live_subject
                ON webauthn_recovery_ceremonies (user_id)
                WHERE status IN ('pending_candidate', 'prepared');

            CREATE UNIQUE INDEX IF NOT EXISTS webauthn_recovery_one_live_session
                ON webauthn_recovery_ceremonies (oidc_session_id)
                WHERE status IN ('pending_candidate', 'prepared');

            CREATE INDEX IF NOT EXISTS webauthn_recovery_status_expiry
                ON webauthn_recovery_ceremonies (status, expires_at);

            CREATE TABLE IF NOT EXISTS webauthn_recovery_revocations (
                id TEXT PRIMARY KEY,
                nonce TEXT NOT NULL UNIQUE,
                user_id TEXT NOT NULL,
                oidc_session_id TEXT NOT NULL,
                pending_token_digest TEXT NOT NULL,
                oidc_token_digest TEXT NOT NULL,
                roles_json TEXT NOT NULL,
                identity_digest TEXT NOT NULL,
                session_expires_at TEXT NOT NULL,
                pending_expires_at TEXT NOT NULL,
                reason TEXT NOT NULL,
                credential_history_digest TEXT NOT NULL,
                credential_history_count BIGINT NOT NULL,
                active_credential_count BIGINT NOT NULL,
                active_credential_record_id TEXT NOT NULL,
                active_credential_id_digest TEXT NOT NULL,
                trust_bundle_digest TEXT NOT NULL,
                trust_bundle_sequence BIGINT NOT NULL,
                trust_bundle_rollback_epoch BIGINT NOT NULL,
                trust_signing_key_id TEXT NOT NULL,
                auth_policy_digest TEXT NOT NULL,
                recovery_root_key_id TEXT NOT NULL,
                recovery_root_provider TEXT NOT NULL,
                recovery_audience TEXT NOT NULL,
                root_sequence BIGINT NOT NULL,
                statement_json TEXT NOT NULL,
                statement_digest TEXT NOT NULL UNIQUE,
                authorization_json TEXT,
                authorization_digest TEXT UNIQUE,
                signature_digest TEXT UNIQUE,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                CHECK (active_credential_count = 1),
                CHECK (credential_history_count > 0),
                CHECK (root_sequence > 0),
                CHECK (status IN ('prepared', 'consumed', 'expired'))
            );

            CREATE UNIQUE INDEX IF NOT EXISTS webauthn_recovery_revocation_one_live_subject
                ON webauthn_recovery_revocations (user_id)
                WHERE status = 'prepared';

            CREATE UNIQUE INDEX IF NOT EXISTS webauthn_recovery_revocation_one_live_session
                ON webauthn_recovery_revocations (oidc_session_id)
                WHERE status = 'prepared';

            CREATE INDEX IF NOT EXISTS webauthn_recovery_revocation_status_expiry
                ON webauthn_recovery_revocations (status, expires_at);
            """


def metadata_initialization_index_source() -> str:
    """Final indexes installed after compatibility columns and backfills."""
    return """
            CREATE INDEX IF NOT EXISTS policy_state_bundles_dispatch_deadline
                ON policy_state_bundles (state, dispatch_deadline_at_epoch_ms, reservation_id);
            CREATE INDEX IF NOT EXISTS policy_state_bundles_reservation_deadline
                ON policy_state_bundles (state, reservation_deadline_at_epoch_ms, reservation_id);
            CREATE UNIQUE INDEX IF NOT EXISTS approval_grants_reserved_attempt
                ON approval_grants (reserved_attempt_id)
                WHERE reserved_attempt_id IS NOT NULL;
            CREATE INDEX IF NOT EXISTS control_plane_approvals_webauthn_lookup
                ON control_plane_approvals (approver_webauthn_credential_id, status);
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_attestation_challenge
                ON setup_sessions (attestation_challenge_digest)
                WHERE attestation_challenge_digest IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_enrollment_verifier_receipt
                ON setup_sessions (enrollment_verifier_receipt_digest)
                WHERE enrollment_verifier_receipt_digest IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_runtime_evidence
                ON setup_sessions (runtime_evidence_digest)
                WHERE runtime_evidence_digest IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_hardware_assurance
                ON setup_sessions (hardware_assurance_digest)
                WHERE hardware_assurance_digest IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_hardware_verification_receipt
                ON setup_sessions (hardware_verification_receipt_digest)
                WHERE hardware_verification_receipt_digest IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_final_consumption
                ON setup_sessions (final_consumption_id)
                WHERE final_consumption_id IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_final_receipt
                ON setup_sessions (final_receipt_digest)
                WHERE final_receipt_digest IS NOT NULL;
            CREATE INDEX IF NOT EXISTS oidc_browser_sessions_pending_expiry
                ON oidc_browser_sessions (status, pending_expires_at);
            CREATE INDEX IF NOT EXISTS webauthn_challenges_type_user_state
                ON webauthn_challenges (challenge_type, user_id, used_at, expires_at);
            CREATE INDEX IF NOT EXISTS webauthn_challenges_type_scope_state
                ON webauthn_challenges (challenge_type, scope_key, used_at, expires_at);
            CREATE INDEX IF NOT EXISTS webauthn_challenges_live_expiry
                ON webauthn_challenges (used_at, expires_at);
            CREATE INDEX IF NOT EXISTS webauthn_challenges_user_created
                ON webauthn_challenges (user_id, created_at);
            CREATE INDEX IF NOT EXISTS webauthn_challenges_created
                ON webauthn_challenges (created_at);
            CREATE UNIQUE INDEX IF NOT EXISTS webauthn_challenges_one_live_oidc_binding
                ON webauthn_challenges (challenge_type, user_id, scope_key)
                WHERE challenge_type = 'oidc-session-binding'
                    AND used_at IS NULL AND scope_key IS NOT NULL;
            CREATE INDEX IF NOT EXISTS webauthn_credentials_user_active
                ON webauthn_credentials (user_id, revoked_at, created_at);
            CREATE INDEX IF NOT EXISTS webauthn_credentials_user_class_active
                ON webauthn_credentials (user_id, authenticator_class, revoked_at);
            CREATE INDEX IF NOT EXISTS oidc_login_states_source_expiry
                ON oidc_login_states (source_key, expires_at);
            CREATE UNIQUE INDEX IF NOT EXISTS approval_requests_one_pending_key
                ON approval_requests (pending_key)
                WHERE status = 'pending';
            """


def metadata_schema_source(*, include_initialization_indexes: bool = True) -> str:
    from serverware import authority_native_activation_schema
    from serverware import authority_native_jit_retention_schema
    source = (metadata_base_schema_source() + authority_native_activation_schema.source()
        + authority_native_jit_retention_schema.source() + authority_v9_schema_source())
    if include_initialization_indexes:
        source += metadata_initialization_index_source()
    return source
