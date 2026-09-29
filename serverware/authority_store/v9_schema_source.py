"""Pure source-owned v9 DDL extension; callers own installation admission."""
from __future__ import annotations

from serverware import authority_contract


def planner_retention_guard_sql(namespace: str) -> str:
    """Post-table PostgreSQL enforcement; never migrate or repair old rows."""
    if (type(namespace) is not str or len(namespace) < 3 or "\x00" in namespace
            or not namespace.startswith('"') or not namespace.endswith('"')
            or '"' in namespace[1:-1].replace('""', '')):
        raise ValueError("retention guard namespace is not one quoted identifier")
    def changed(columns):
        return "ROW(" + ", ".join("NEW." + column for column in columns) + ") IS DISTINCT FROM ROW(" + ", ".join("OLD." + column for column in columns) + ")"
    reservation = changed(authority_contract.PLANNER_RESERVATION_IMMUTABLE_COLUMNS)
    payload = changed(authority_contract.PLANNER_PAYLOAD_IMMUTABLE_COLUMNS)
    terminal = changed(authority_contract.PLANNER_TERMINAL_IMMUTABLE_COLUMNS)
    parent = namespace + ".policy_authority_planner_transactions"
    child = namespace + ".policy_authority_revocation_retained_plans"
    parent_literal = parent.replace("'", "''")
    return f"""
        DO $serverware_retained_fk$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_constraint
                WHERE conrelid = '{parent_literal}'::pg_catalog.regclass
                  AND conname = 'serverware_planner_retained_record_fk'
            ) THEN
                ALTER TABLE {parent}
                    ADD CONSTRAINT serverware_planner_retained_record_fk
                    FOREIGN KEY (planner_transaction_id, plan_protocol, retained_record_digest)
                    REFERENCES {child} (planner_transaction_id, plan_protocol, retained_record_digest)
                    DEFERRABLE INITIALLY DEFERRED;
            END IF;
        END;
        $serverware_retained_fk$;
        CREATE OR REPLACE FUNCTION {namespace}.serverware_guard_planner_retention()
        RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $serverware_retention$
        BEGIN
            IF {reservation}
                OR (OLD.exact_plan_base64url IS NOT NULL AND ({payload}))
                OR (OLD.status IN ('consumed', 'failed') AND ({payload} OR {terminal}))
                OR (OLD.status = 'reserved' AND NEW.status NOT IN ('reserved', 'planned', 'failed'))
                OR (OLD.status = 'planned' AND NEW.status = 'reserved')
            THEN
                RAISE EXCEPTION 'planner reservation and retained evidence are immutable';
            END IF;
            RETURN NEW;
        END;
        $serverware_retention$;
        DROP TRIGGER IF EXISTS serverware_planner_retention_guard ON {parent};
        CREATE TRIGGER serverware_planner_retention_guard
            BEFORE UPDATE ON {parent} FOR EACH ROW
            EXECUTE FUNCTION {namespace}.serverware_guard_planner_retention();
    """


def planner_retention_sqlite_guards_sql() -> str:
    """Keep SQLite v3-only while enforcing its actual reservation immutability."""
    def changed(columns):
        return " OR ".join("NEW." + column + " IS NOT OLD." + column for column in columns)
    reservation = changed(authority_contract.PLANNER_RESERVATION_IMMUTABLE_COLUMNS)
    payload = changed(authority_contract.PLANNER_PAYLOAD_IMMUTABLE_COLUMNS)
    terminal = changed(authority_contract.PLANNER_TERMINAL_IMMUTABLE_COLUMNS)
    return f"""
        CREATE TRIGGER IF NOT EXISTS serverware_planner_retention_insert_guard
        BEFORE INSERT ON policy_authority_planner_transactions
        WHEN NEW.plan_protocol <> 'v3' OR NEW.retained_record_digest IS NOT NULL
        BEGIN SELECT RAISE(ABORT, 'SQLite retained revocation admission is disabled'); END;
        CREATE TRIGGER IF NOT EXISTS serverware_planner_retention_guard
        BEFORE UPDATE ON policy_authority_planner_transactions
        WHEN NEW.plan_protocol <> 'v3' OR NEW.retained_record_digest IS NOT NULL
            OR {reservation}
            OR (OLD.exact_plan_base64url IS NOT NULL AND ({payload}))
            OR (OLD.status IN ('consumed', 'failed') AND ({payload} OR {terminal}))
            OR (OLD.status = 'reserved' AND NEW.status NOT IN ('reserved', 'planned', 'failed'))
            OR (OLD.status = 'planned' AND NEW.status = 'reserved')
        BEGIN SELECT RAISE(ABORT, 'planner reservation and retained evidence are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS serverware_retained_sqlite_insert_guard
        BEFORE INSERT ON policy_authority_revocation_retained_plans
        BEGIN SELECT RAISE(ABORT, 'SQLite retained revocation admission is disabled'); END;
        CREATE TRIGGER IF NOT EXISTS serverware_writer_request_sqlite_insert_guard
        BEFORE INSERT ON policy_authority_revocation_writer_requests
        BEGIN SELECT RAISE(ABORT, 'SQLite writer request custody is disabled'); END;
        CREATE TRIGGER IF NOT EXISTS serverware_writer_ack_sqlite_insert_guard
        BEFORE INSERT ON policy_authority_revocation_writer_acknowledgments
        BEGIN SELECT RAISE(ABORT, 'SQLite writer acknowledgment custody is disabled'); END;
        CREATE TRIGGER IF NOT EXISTS serverware_webauthn_evidence_retained_sqlite_insert_guard
        BEFORE INSERT ON policy_authority_webauthn_evidence_retained_plans
        BEGIN SELECT RAISE(ABORT, 'SQLite retained WebAuthn evidence admission is disabled'); END;
        CREATE TRIGGER IF NOT EXISTS serverware_webauthn_transition_retained_sqlite_insert_guard
        BEFORE INSERT ON policy_authority_webauthn_transition_retained_plans
        BEGIN SELECT RAISE(ABORT, 'SQLite retained WebAuthn transition admission is disabled'); END;
        CREATE TRIGGER IF NOT EXISTS serverware_current_root_marker_sqlite_insert_guard
        BEFORE INSERT ON policy_authority_current_root_commit_markers
        BEGIN SELECT RAISE(ABORT, 'SQLite current-root commit marker admission is disabled'); END;
        CREATE TRIGGER IF NOT EXISTS serverware_successor_custody_sqlite_insert_guard
        BEFORE INSERT ON policy_authority_successor_execution_custody
        BEGIN SELECT RAISE(ABORT, 'SQLite successor execution custody admission is disabled'); END;
    """


def capability_retention_guard_sql(namespace: str) -> str:
    """Bind immutable successor custody without admitting an issuer/executor."""
    if (type(namespace) is not str or len(namespace) < 3 or "\x00" in namespace
            or not namespace.startswith('"') or not namespace.endswith('"')
            or '"' in namespace[1:-1].replace('""', '')):
        raise ValueError("capability retention namespace is not one quoted identifier")
    def changed(columns):
        return "ROW(" + ", ".join("NEW." + column for column in columns) + ") IS DISTINCT FROM ROW(" + ", ".join("OLD." + column for column in columns) + ")"
    identity = changed(authority_contract.WRITER_CAPABILITY_IMMUTABLE_COLUMNS)
    reservation = changed(authority_contract.WRITER_CAPABILITY_RESERVATION_COLUMNS)
    terminal = changed(authority_contract.WRITER_CAPABILITY_TERMINAL_COLUMNS)
    terminal_data = changed(authority_contract.WRITER_CAPABILITY_TERMINAL_COLUMNS[1:])
    parent = namespace + ".policy_authority_writer_capabilities"
    child = namespace + ".policy_authority_revocation_retained_capabilities"
    parent_literal = parent.replace("'", "''")
    return f"""
        DO $serverware_capability_retained_fk$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_constraint
                WHERE conrelid = '{parent_literal}'::pg_catalog.regclass
                  AND conname = 'serverware_writer_capability_retained_fk'
            ) THEN
                ALTER TABLE {parent}
                    ADD CONSTRAINT serverware_writer_capability_retained_fk
                    FOREIGN KEY (capability_id, capability_protocol, capability_record_digest,
                                 planner_transaction_id, envelope_id)
                    REFERENCES {child} (capability_id, capability_protocol, capability_record_digest,
                                        planner_transaction_id, execution_envelope_id)
                    DEFERRABLE INITIALLY DEFERRED;
            END IF;
        END;
        $serverware_capability_retained_fk$;
        CREATE OR REPLACE FUNCTION {namespace}.serverware_guard_capability_retention()
        RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $serverware_capability_retention$
        BEGIN
            IF NEW.capability_protocol IS DISTINCT FROM OLD.capability_protocol
                OR (OLD.capability_protocol = 'revocation-v4' AND (
                    {identity}
                    OR ((OLD.writer_token_digest IS NOT NULL
                         OR OLD.reserved_at_epoch_ns IS NOT NULL
                         OR OLD.reserved_transaction_id IS NOT NULL) AND ({reservation}))
                    OR (OLD.status IN ('reconciled', 'expired', 'failed') AND ({terminal}))
                    OR (OLD.status = 'committed' AND
                        (NEW.status NOT IN ('committed', 'reconciled') OR {terminal_data}))
                    OR (OLD.status = 'issued' AND NEW.status NOT IN
                        ('issued', 'reserved', 'committed', 'expired', 'failed'))
                    OR (OLD.status = 'reserved' AND NEW.status NOT IN ('reserved', 'committed', 'expired'))
                ))
            THEN RAISE EXCEPTION 'capability identity and retained evidence are immutable'; END IF;
            RETURN NEW;
        END;
        $serverware_capability_retention$;
        DROP TRIGGER IF EXISTS serverware_capability_retention_guard ON {parent};
        CREATE TRIGGER serverware_capability_retention_guard
            BEFORE UPDATE ON {parent} FOR EACH ROW
            EXECUTE FUNCTION {namespace}.serverware_guard_capability_retention();
    """


def capability_retention_sqlite_guards_sql() -> str:
    """Deny successor custody on SQLite without changing legacy v3 recovery."""
    return """
        CREATE TRIGGER IF NOT EXISTS serverware_capability_retention_insert_guard
        BEFORE INSERT ON policy_authority_writer_capabilities
        WHEN NEW.capability_protocol <> 'v3' OR NEW.capability_record_digest IS NOT NULL
        BEGIN SELECT RAISE(ABORT, 'SQLite retained capability admission is disabled'); END;
        CREATE TRIGGER IF NOT EXISTS serverware_capability_retention_guard
        BEFORE UPDATE ON policy_authority_writer_capabilities
        WHEN NEW.capability_protocol IS NOT OLD.capability_protocol
            OR NEW.capability_protocol <> 'v3' OR NEW.capability_record_digest IS NOT NULL
        BEGIN SELECT RAISE(ABORT, 'SQLite retained capability admission is disabled'); END;
        CREATE TRIGGER IF NOT EXISTS serverware_capability_sidecar_sqlite_insert_guard
        BEFORE INSERT ON policy_authority_revocation_retained_capabilities
        BEGIN SELECT RAISE(ABORT, 'SQLite retained capability admission is disabled'); END;
    """


def authority_v9_schema_source() -> str:
    return """
        CREATE TABLE IF NOT EXISTS
            policy_authority_v9_offline_migration_receipts (
                contract_id TEXT PRIMARY KEY,
                source_version BIGINT NOT NULL,
                target_version BIGINT NOT NULL,
                migration_name TEXT NOT NULL,
                migration_sha256 TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                before_manifest_json TEXT NOT NULL,
                before_manifest_digest TEXT NOT NULL,
                before_row_counts_json TEXT NOT NULL,
                before_row_counts_digest TEXT NOT NULL,
                after_manifest_json TEXT NOT NULL,
                after_manifest_digest TEXT NOT NULL,
                after_row_counts_json TEXT NOT NULL,
                after_row_counts_digest TEXT NOT NULL,
                operation_contract_digest TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                receipt_digest TEXT NOT NULL UNIQUE,
                signer_identity_digest TEXT NOT NULL,
                signer_public_key_base64url TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                detached_signature TEXT NOT NULL,
                detached_signature_digest TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                CHECK (
                    contract_id =
                    'serverware.policyCandidateAuthorityOfflineMigration/v2:v8-to-v9'
                ),
                CHECK (source_version = 8),
                CHECK (target_version = 9),
                CHECK (
                    migration_name =
                    'policy-candidate-authority-v8-to-v9'
                ),
                CHECK (
                    length(migration_sha256) = 71
                ),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                ),
                CHECK (status = 'completed'),
                CHECK (length(before_manifest_json) BETWEEN 2 AND 67108864),
                CHECK (length(after_manifest_json) BETWEEN 2 AND 67108864),
                CHECK (length(before_row_counts_json) BETWEEN 2 AND 4194304),
                CHECK (length(after_row_counts_json) BETWEEN 2 AND 4194304),
                CHECK (length(receipt_json) BETWEEN 2 AND 67108864),
                CHECK (signature_algorithm = 'Ed25519')
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_authorization_dependency_manifests (
                operation TEXT NOT NULL,
                ordinal BIGINT NOT NULL,
                table_name TEXT NOT NULL,
                key_columns_json TEXT NOT NULL,
                predicate_kind TEXT NOT NULL,
                exact_absence BIGINT NOT NULL,
                entry_digest TEXT NOT NULL,
                manifest_digest TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                PRIMARY KEY (operation, ordinal),
                UNIQUE (operation, table_name),
                CHECK (ordinal > 0),
                CHECK (exact_absence = 1),
                CHECK (
                    predicate_kind =
                    'primary-key-full-row-and-authenticated-root-v1'
                ),
                CHECK (length(key_columns_json) BETWEEN 2 AND 4194304),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_operation_mutation_templates (
                operation TEXT NOT NULL,
                template_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                mutation TEXT NOT NULL,
                before_state TEXT NOT NULL,
                after_state TEXT NOT NULL,
                predicate_kind TEXT NOT NULL,
                cardinality BIGINT NOT NULL,
                template_json TEXT NOT NULL,
                operation_manifest_digest TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                PRIMARY KEY (operation, template_id),
                UNIQUE (operation, table_name, mutation),
                CHECK (mutation IN ('INSERT', 'UPDATE', 'DELETE')),
                CHECK (before_state IN ('absent', 'present')),
                CHECK (after_state IN ('absent', 'present')),
                CHECK (
                    (mutation = 'INSERT'
                        AND before_state = 'absent'
                        AND after_state = 'present')
                    OR
                    (mutation = 'UPDATE'
                        AND before_state = 'present'
                        AND after_state = 'present')
                    OR
                    (mutation = 'DELETE'
                        AND before_state = 'present'
                        AND after_state = 'absent')
                ),
                CHECK (
                    predicate_kind =
                    'exact-primary-key-and-full-row-cas-v1'
                ),
                CHECK (cardinality = 1),
                CHECK (length(template_json) BETWEEN 2 AND 4194304),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_webauthn_assertion_evidence (
                assertion_evidence_digest TEXT PRIMARY KEY,
                operation TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                challenge_id TEXT NOT NULL UNIQUE,
                challenge_digest TEXT NOT NULL,
                client_challenge_digest TEXT NOT NULL,
                credential_record_id TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                credential_policy_digest TEXT NOT NULL,
                authenticator_data_base64url TEXT NOT NULL,
                authenticator_data_digest TEXT NOT NULL,
                client_data_json_base64url TEXT NOT NULL,
                client_data_json_digest TEXT NOT NULL,
                signature_base64url TEXT NOT NULL,
                signature_digest TEXT NOT NULL,
                rp_id TEXT NOT NULL,
                rp_id_hash_digest TEXT NOT NULL,
                origin TEXT NOT NULL,
                flags BIGINT NOT NULL,
                user_present BIGINT NOT NULL,
                user_verified BIGINT NOT NULL,
                prior_counter BIGINT NOT NULL,
                counter BIGINT NOT NULL,
                trust_high_water_digest TEXT NOT NULL,
                metadata_publication_sequence BIGINT NOT NULL,
                verifier_session_identity_digest TEXT NOT NULL,
                verifier_measurement_digest TEXT NOT NULL,
                verifier_attestation_receipt_digest TEXT NOT NULL,
                verified_assertion_receipt_digest TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                verified_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                source_revision TEXT NOT NULL,
                UNIQUE (operation_id, request_digest, capability_id),
                CHECK (flags >= 0),
                CHECK (user_present = 1),
                CHECK (user_verified = 1),
                CHECK (prior_counter >= 0),
                CHECK (counter > prior_counter),
                CHECK (metadata_publication_sequence > 0),
                CHECK (verified_at_epoch_ns >= 0),
                CHECK (expires_at_epoch_ns > verified_at_epoch_ns),
                CHECK (length(evidence_json) BETWEEN 2 AND 4194304),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_authorization_projections (
                authorization_projection_digest TEXT PRIMARY KEY,
                planner_transaction_id TEXT NOT NULL UNIQUE,
                operation TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                operation_contract_digest TEXT NOT NULL,
                authorization_reads_json TEXT NOT NULL,
                authorization_reads_digest TEXT NOT NULL,
                source_rows_json TEXT NOT NULL,
                source_rows_digest TEXT NOT NULL,
                source_high_water_digest TEXT NOT NULL,
                approver_policy_digest TEXT,
                assertion_evidence_digest TEXT,
                projection_json TEXT NOT NULL,
                verifier_session_identity_digest TEXT NOT NULL,
                verifier_measurement_digest TEXT NOT NULL,
                verifier_attestation_receipt_digest TEXT NOT NULL,
                created_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                source_revision TEXT NOT NULL,
                UNIQUE (operation_id, request_digest, capability_id),
                CHECK (
                    length(authorization_reads_json)
                    BETWEEN 2 AND 4194304
                ),
                CHECK (length(source_rows_json) BETWEEN 2 AND 67108864),
                CHECK (length(projection_json) BETWEEN 2 AND 4194304),
                CHECK (created_at_epoch_ns >= 0),
                CHECK (expires_at_epoch_ns > created_at_epoch_ns),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_execution_envelopes (
                envelope_id TEXT PRIMARY KEY,
                parent_envelope_id TEXT,
                purpose TEXT NOT NULL,
                operation TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                capability_id TEXT NOT NULL UNIQUE,
                planner_transaction_id TEXT NOT NULL UNIQUE,
                authorization_projection_digest TEXT NOT NULL,
                operation_contract_digest TEXT NOT NULL,
                exact_request_base64url TEXT NOT NULL,
                exact_request_bytes_digest TEXT NOT NULL,
                exact_request_byte_count BIGINT NOT NULL,
                deadline_monotonic_ns BIGINT NOT NULL,
                deadline_epoch_ns BIGINT NOT NULL,
                fence BIGINT NOT NULL,
                status TEXT NOT NULL,
                exact_response_base64url TEXT,
                exact_response_bytes_digest TEXT,
                exact_response_byte_count BIGINT,
                result_digest TEXT,
                terminal_receipt_json TEXT,
                terminal_receipt_digest TEXT,
                failure_code TEXT,
                failure_digest TEXT,
                reserved_at_epoch_ns BIGINT NOT NULL,
                terminal_at_epoch_ns BIGINT,
                source_revision TEXT NOT NULL,
                UNIQUE (envelope_id, planner_transaction_id),
                UNIQUE (purpose, request_digest, fence),
                CHECK (purpose = 'execute-v9'),
                CHECK (exact_request_byte_count BETWEEN 2 AND 4194304),
                CHECK (deadline_monotonic_ns > 0),
                CHECK (deadline_epoch_ns > reserved_at_epoch_ns),
                CHECK (fence > 0),
                CHECK (status IN ('reserved', 'committed', 'failed')),
                CHECK (
                    (status = 'reserved'
                        AND exact_response_base64url IS NULL
                        AND exact_response_bytes_digest IS NULL
                        AND exact_response_byte_count IS NULL
                        AND result_digest IS NULL
                        AND terminal_receipt_json IS NULL
                        AND terminal_receipt_digest IS NULL
                        AND failure_code IS NULL
                        AND failure_digest IS NULL
                        AND terminal_at_epoch_ns IS NULL)
                    OR (
                        status = 'committed'
                        AND exact_response_base64url IS NOT NULL
                        AND exact_response_bytes_digest IS NOT NULL
                        AND exact_response_byte_count BETWEEN 2 AND 67108864
                        AND result_digest IS NOT NULL
                        AND terminal_receipt_json IS NOT NULL
                        AND terminal_receipt_digest IS NOT NULL
                        AND length(terminal_receipt_json)
                            BETWEEN 2 AND 4194304
                        AND failure_code IS NULL
                        AND failure_digest IS NULL
                        AND terminal_at_epoch_ns IS NOT NULL)
                    OR (
                        status = 'failed'
                        AND exact_response_base64url IS NOT NULL
                        AND exact_response_bytes_digest IS NOT NULL
                        AND exact_response_byte_count BETWEEN 2 AND 67108864
                        AND result_digest IS NULL
                        AND terminal_receipt_json IS NULL
                        AND terminal_receipt_digest IS NULL
                        AND failure_code IS NOT NULL
                        AND failure_digest IS NOT NULL
                        AND terminal_at_epoch_ns IS NOT NULL)
                ),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_planner_transactions (
                planner_transaction_id TEXT PRIMARY KEY,
                plan_protocol TEXT NOT NULL DEFAULT 'v3',
                retained_record_digest TEXT,
                operation TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                capability_id TEXT NOT NULL UNIQUE,
                operation_contract_digest TEXT NOT NULL,
                query_manifest_digest TEXT NOT NULL,
                selected_business_rows_json TEXT NOT NULL,
                selected_business_rows_digest TEXT NOT NULL,
                mutation_plan_json TEXT NOT NULL,
                mutation_plan_digest TEXT NOT NULL,
                work_units BIGINT NOT NULL,
                authority_root_set_before_digest TEXT NOT NULL,
                authorization_projection_digest TEXT,
                authority_snapshot_digest TEXT,
                planner_session_identity_digest TEXT NOT NULL,
                planner_measurement_digest TEXT NOT NULL,
                planner_attestation_receipt_digest TEXT NOT NULL,
                deadline_monotonic_ns BIGINT NOT NULL,
                deadline_epoch_ns BIGINT NOT NULL,
                fence BIGINT NOT NULL,
                status TEXT NOT NULL,
                exact_plan_base64url TEXT,
                exact_plan_bytes_digest TEXT,
                exact_plan_byte_count BIGINT,
                exact_response_base64url TEXT,
                exact_response_bytes_digest TEXT,
                exact_response_byte_count BIGINT,
                terminal_receipt_json TEXT,
                terminal_receipt_digest TEXT,
                reserved_at_epoch_ns BIGINT NOT NULL,
                planned_at_epoch_ns BIGINT,
                terminal_at_epoch_ns BIGINT,
                source_revision TEXT NOT NULL,
                UNIQUE (planner_transaction_id, plan_protocol, retained_record_digest),
                CHECK (plan_protocol IN ('v3', 'revocation-v4')),
                CHECK (
                    retained_record_digest IS NULL
                    OR retained_record_digest ~ '^sha256:[0-9a-f]{64}$'
                ),
                CHECK (
                    (plan_protocol = 'v3' AND retained_record_digest IS NULL)
                    OR (plan_protocol = 'revocation-v4'
                        AND operation = 'webauthn.credential.revoke'
                        AND (
                            (retained_record_digest IS NULL
                                AND status IN ('reserved', 'failed')
                                AND authorization_projection_digest IS NULL
                                AND authority_snapshot_digest IS NULL
                                AND exact_plan_base64url IS NULL
                                AND exact_plan_bytes_digest IS NULL
                                AND exact_plan_byte_count IS NULL
                                AND planned_at_epoch_ns IS NULL)
                            OR (retained_record_digest IS NOT NULL
                                AND status IN ('planned', 'consumed', 'failed')
                                AND authorization_projection_digest IS NOT NULL
                                AND authority_snapshot_digest IS NOT NULL
                                AND exact_plan_base64url IS NOT NULL
                                AND exact_plan_bytes_digest IS NOT NULL
                                AND exact_plan_byte_count IS NOT NULL
                                AND exact_plan_byte_count BETWEEN 2 AND 67108864
                                AND planned_at_epoch_ns IS NOT NULL)
                        ))
                ),
                CHECK (
                    status IN ('reserved', 'planned', 'consumed', 'failed')
                ),
                CHECK (
                    length(selected_business_rows_json)
                    BETWEEN 2 AND __MAX_PLAN_SELECTED_BYTES__
                ),
                CHECK (length(mutation_plan_json) BETWEEN 2 AND 67108864),
                CHECK (work_units BETWEEN 1 AND __MAX_PLAN_WORK_UNITS__),
                CHECK (deadline_monotonic_ns > 0),
                CHECK (deadline_epoch_ns > reserved_at_epoch_ns),
                CHECK (fence > 0),
                CHECK (
                    (status = 'reserved'
                        AND authorization_projection_digest IS NULL
                        AND authority_snapshot_digest IS NULL
                        AND exact_plan_base64url IS NULL
                        AND exact_plan_bytes_digest IS NULL
                        AND exact_plan_byte_count IS NULL
                        AND exact_response_base64url IS NULL
                        AND exact_response_bytes_digest IS NULL
                        AND exact_response_byte_count IS NULL
                        AND terminal_receipt_json IS NULL
                        AND terminal_receipt_digest IS NULL
                        AND planned_at_epoch_ns IS NULL
                        AND terminal_at_epoch_ns IS NULL)
                    OR (
                        status = 'planned'
                        AND authorization_projection_digest IS NOT NULL
                        AND authority_snapshot_digest IS NOT NULL
                        AND exact_plan_base64url IS NOT NULL
                        AND exact_plan_bytes_digest IS NOT NULL
                        AND exact_plan_byte_count BETWEEN 2 AND 67108864
                        AND planned_at_epoch_ns IS NOT NULL
                        AND exact_response_base64url IS NULL
                        AND exact_response_bytes_digest IS NULL
                        AND exact_response_byte_count IS NULL
                        AND terminal_receipt_json IS NULL
                        AND terminal_receipt_digest IS NULL
                        AND terminal_at_epoch_ns IS NULL)
                    OR (
                        status = 'consumed'
                        AND authorization_projection_digest IS NOT NULL
                        AND authority_snapshot_digest IS NOT NULL
                        AND exact_plan_base64url IS NOT NULL
                        AND exact_plan_bytes_digest IS NOT NULL
                        AND exact_plan_byte_count BETWEEN 2 AND 67108864
                        AND exact_response_base64url IS NOT NULL
                        AND exact_response_bytes_digest IS NOT NULL
                        AND exact_response_byte_count
                            BETWEEN 2 AND 67108864
                        AND terminal_receipt_json IS NOT NULL
                        AND terminal_receipt_digest IS NOT NULL
                        AND length(terminal_receipt_json)
                            BETWEEN 2 AND 4194304
                        AND planned_at_epoch_ns IS NOT NULL
                        AND terminal_at_epoch_ns IS NOT NULL)
                    OR (
                        status = 'failed'
                        AND exact_response_base64url IS NOT NULL
                        AND exact_response_bytes_digest IS NOT NULL
                        AND exact_response_byte_count
                            BETWEEN 2 AND 67108864
                        AND terminal_receipt_json IS NULL
                        AND terminal_receipt_digest IS NULL
                        AND terminal_at_epoch_ns IS NOT NULL)
                ),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_revocation_retained_plans (
                planner_transaction_id TEXT PRIMARY KEY,
                plan_protocol TEXT NOT NULL,
                exact_envelope_base64url TEXT NOT NULL,
                exact_envelope_bytes_digest TEXT NOT NULL,
                exact_envelope_byte_count BIGINT NOT NULL,
                evaluation_context_base64url TEXT NOT NULL,
                evaluation_context_bytes_digest TEXT NOT NULL,
                evaluation_context_byte_count BIGINT NOT NULL,
                planner_key_digest TEXT NOT NULL,
                verifier_key_digest TEXT NOT NULL,
                retained_record_digest TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                UNIQUE (planner_transaction_id, plan_protocol, retained_record_digest),
                CONSTRAINT serverware_revocation_retained_parent_fk
                    FOREIGN KEY (planner_transaction_id, plan_protocol, retained_record_digest)
                    REFERENCES policy_authority_planner_transactions
                        (planner_transaction_id, plan_protocol, retained_record_digest)
                    DEFERRABLE INITIALLY DEFERRED,
                CHECK (plan_protocol = 'revocation-v4'),
                CHECK (length(planner_transaction_id) BETWEEN 1 AND 256),
                CHECK (exact_envelope_byte_count BETWEEN 2 AND 67108864),
                CHECK (evaluation_context_byte_count BETWEEN 2 AND 524288),
                CHECK (
                    length(exact_envelope_base64url) = (4 * exact_envelope_byte_count + 2) / 3
                    AND exact_envelope_base64url ~ '^[A-Za-z0-9_-]+$'
                    AND length(evaluation_context_base64url) = (4 * evaluation_context_byte_count + 2) / 3
                    AND evaluation_context_base64url ~ '^[A-Za-z0-9_-]+$'
                ),
                CHECK (
                    exact_envelope_byte_count % 3 = 0
                    OR (exact_envelope_byte_count % 3 = 1
                        AND substr(exact_envelope_base64url, length(exact_envelope_base64url), 1) IN ('A', 'Q', 'g', 'w'))
                    OR (exact_envelope_byte_count % 3 = 2
                        AND substr(exact_envelope_base64url, length(exact_envelope_base64url), 1) IN
                            ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8'))
                ),
                CHECK (
                    evaluation_context_byte_count % 3 = 0
                    OR (evaluation_context_byte_count % 3 = 1
                        AND substr(evaluation_context_base64url, length(evaluation_context_base64url), 1) IN ('A', 'Q', 'g', 'w'))
                    OR (evaluation_context_byte_count % 3 = 2
                        AND substr(evaluation_context_base64url, length(evaluation_context_base64url), 1) IN
                            ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8'))
                ),
                CHECK (
                    exact_envelope_bytes_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND evaluation_context_bytes_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND planner_key_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND verifier_key_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND retained_record_digest ~ '^sha256:[0-9a-f]{64}$'
                ),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_webauthn_evidence_retained_plans (
                retained_record_digest TEXT PRIMARY KEY NOT NULL,
                plan_protocol TEXT NOT NULL,
                operation TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                configuration_digest TEXT NOT NULL,
                plan_digest TEXT NOT NULL,
                exact_envelope_base64url TEXT NOT NULL,
                exact_envelope_bytes_digest TEXT NOT NULL,
                exact_envelope_byte_count BIGINT NOT NULL,
                original_inputs_base64url TEXT NOT NULL,
                original_inputs_bytes_digest TEXT NOT NULL,
                original_inputs_byte_count BIGINT NOT NULL,
                evaluation_context_base64url TEXT NOT NULL,
                evaluation_context_bytes_digest TEXT NOT NULL,
                evaluation_context_byte_count BIGINT NOT NULL,
                planner_key_digest TEXT NOT NULL,
                evidence_key_digest TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                retained_at_epoch_ns BIGINT NOT NULL,
                CHECK (plan_protocol = 'webauthn-evidence-admission-v1'),
                CHECK (operation IN ('webauthn.registration.evidence.admit', 'webauthn.trust.installation.admit')),
                CHECK (retained_at_epoch_ns BETWEEN 1 AND 9223372036854775807),
                CHECK (exact_envelope_byte_count BETWEEN 2 AND 67108864),
                CHECK (original_inputs_byte_count BETWEEN 2 AND 67108864),
                CHECK (evaluation_context_byte_count BETWEEN 2 AND 67108864),
                CHECK (
                    length(exact_envelope_base64url) = (4 * exact_envelope_byte_count + 2) / 3
                    AND exact_envelope_base64url ~ '^[A-Za-z0-9_-]+$'
                    AND length(original_inputs_base64url) = (4 * original_inputs_byte_count + 2) / 3
                    AND original_inputs_base64url ~ '^[A-Za-z0-9_-]+$'
                    AND length(evaluation_context_base64url) = (4 * evaluation_context_byte_count + 2) / 3
                    AND evaluation_context_base64url ~ '^[A-Za-z0-9_-]+$'
                ),
                CHECK (
                    exact_envelope_byte_count % 3 = 0
                    OR (exact_envelope_byte_count % 3 = 1
                        AND substr(exact_envelope_base64url, length(exact_envelope_base64url), 1) IN ('A', 'Q', 'g', 'w'))
                    OR (exact_envelope_byte_count % 3 = 2
                        AND substr(exact_envelope_base64url, length(exact_envelope_base64url), 1) IN
                            ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8'))
                ),
                CHECK (
                    original_inputs_byte_count % 3 = 0
                    OR (original_inputs_byte_count % 3 = 1
                        AND substr(original_inputs_base64url, length(original_inputs_base64url), 1) IN ('A', 'Q', 'g', 'w'))
                    OR (original_inputs_byte_count % 3 = 2
                        AND substr(original_inputs_base64url, length(original_inputs_base64url), 1) IN
                            ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8'))
                ),
                CHECK (
                    evaluation_context_byte_count % 3 = 0
                    OR (evaluation_context_byte_count % 3 = 1
                        AND substr(evaluation_context_base64url, length(evaluation_context_base64url), 1) IN ('A', 'Q', 'g', 'w'))
                    OR (evaluation_context_byte_count % 3 = 2
                        AND substr(evaluation_context_base64url, length(evaluation_context_base64url), 1) IN
                            ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8'))
                ),
                CHECK (
                    retained_record_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND operation_id ~ '^sha256:[0-9a-f]{64}$'
                    AND request_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND configuration_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND plan_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND exact_envelope_bytes_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND original_inputs_bytes_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND evaluation_context_bytes_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND planner_key_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND evidence_key_digest ~ '^sha256:[0-9a-f]{64}$'
                ),
                CHECK (source_revision = 'serverware.policyCandidateAuthoritySource/2026-07-30.254')
            );

        -- Original authenticated execution packets are protected framework
        -- custody, never members of primary/count business populations.
        CREATE TABLE IF NOT EXISTS policy_authority_successor_execution_custody (
            pending_decision_digest TEXT NOT NULL,
            packet_digest TEXT NOT NULL UNIQUE,
            packet_json TEXT NOT NULL,
            enrollment_digest TEXT NOT NULL,
            generation_digest TEXT NOT NULL,
            capability_digest TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            fence BIGINT NOT NULL,
            issued_at_epoch_ns BIGINT NOT NULL,
            expires_at_epoch_ns BIGINT NOT NULL,
            issuer_identity_digest TEXT NOT NULL,
            CONSTRAINT policy_authority_successor_execution_custody_pkey PRIMARY KEY (pending_decision_digest),
            UNIQUE (enrollment_digest, capability_digest),
            UNIQUE (enrollment_digest, operation_id),
            UNIQUE (enrollment_digest, fence),
            CHECK (length(packet_json) BETWEEN 2 AND 67108864 AND packet_json ~ '^[ -~]+$'),
            CHECK (fence BETWEEN 1 AND 9223372036854775807),
            CHECK (issued_at_epoch_ns BETWEEN 1 AND 9223372036854775806),
            CHECK (expires_at_epoch_ns > issued_at_epoch_ns
                AND expires_at_epoch_ns <= 9223372036854775807),
            CHECK (pending_decision_digest ~ '^sha256:[0-9a-f]{64}$'
                AND packet_digest ~ '^sha256:[0-9a-f]{64}$'
                AND enrollment_digest ~ '^sha256:[0-9a-f]{64}$'
                AND generation_digest ~ '^sha256:[0-9a-f]{64}$'
                AND capability_digest ~ '^sha256:[0-9a-f]{64}$'
                AND operation_id ~ '^sha256:[0-9a-f]{64}$'
                AND issuer_identity_digest ~ '^sha256:[0-9a-f]{64}$')
        );

        -- This framework-only row is outside primary and counted business
        -- roots. A later postcommit receipt may bind it, never the reverse.
        -- Only the dedicated protected successor function may insert a marker;
        -- neither its executor role nor any other runtime role has direct DML.
        CREATE TABLE IF NOT EXISTS
            policy_authority_current_root_commit_markers (
                pending_decision_digest TEXT PRIMARY KEY NOT NULL,
                source_revision TEXT NOT NULL,
                database_id TEXT NOT NULL,
                enrollment_digest TEXT NOT NULL,
                generation_digest TEXT NOT NULL,
                pending_request_digest TEXT NOT NULL UNIQUE,
                pending_sequence BIGINT NOT NULL,
                predecessor_sequence BIGINT NOT NULL,
                predecessor_head_digest TEXT NOT NULL,
                fence BIGINT NOT NULL,
                operation TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                capability_digest TEXT NOT NULL,
                snapshot_digest TEXT NOT NULL,
                before_vector_digest TEXT NOT NULL,
                after_vector_digest TEXT NOT NULL,
                result_digest TEXT NOT NULL,
                UNIQUE (enrollment_digest, fence),
                UNIQUE (enrollment_digest, operation_id),
                UNIQUE (enrollment_digest, capability_digest),
                CHECK (source_revision = 'serverware.policyCandidateAuthoritySource/2026-07-30.254'),
                CHECK (length(database_id) BETWEEN 1 AND 128
                    AND database_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
                CHECK (pending_sequence BETWEEN 1 AND 9223372036854775807),
                CHECK (predecessor_sequence BETWEEN 0 AND 9223372036854775806),
                CHECK (pending_sequence = predecessor_sequence + 1),
                CHECK (fence BETWEEN 1 AND 9223372036854775807),
                CHECK (operation IN ('webauthn.credential.revoke',
                    'webauthn.registration.evidence.admit', 'webauthn.registration.finalize',
                    'webauthn.trust.complete', 'webauthn.trust.installation.admit',
                    'webauthn.trust.stage')),
                CHECK (
                    pending_decision_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND enrollment_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND generation_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND pending_request_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND predecessor_head_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND request_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND operation_id ~ '^sha256:[0-9a-f]{64}$'
                    AND capability_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND snapshot_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND before_vector_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND after_vector_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND result_digest ~ '^sha256:[0-9a-f]{64}$'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_webauthn_transition_retained_plans (
                retained_record_digest TEXT PRIMARY KEY NOT NULL,
                plan_protocol TEXT NOT NULL,
                operation TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                configuration_digest TEXT NOT NULL,
                plan_digest TEXT NOT NULL,
                exact_envelope_base64url TEXT NOT NULL,
                exact_envelope_bytes_digest TEXT NOT NULL,
                exact_envelope_byte_count BIGINT NOT NULL,
                original_proof_base64url TEXT NOT NULL,
                original_proof_bytes_digest TEXT NOT NULL,
                original_proof_byte_count BIGINT NOT NULL,
                original_inputs_base64url TEXT NOT NULL,
                original_inputs_bytes_digest TEXT NOT NULL,
                original_inputs_byte_count BIGINT NOT NULL,
                evaluation_context_base64url TEXT NOT NULL,
                evaluation_context_bytes_digest TEXT NOT NULL,
                evaluation_context_byte_count BIGINT NOT NULL,
                planner_key_digest TEXT NOT NULL,
                operation_key_digest TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                retained_at_epoch_ns BIGINT NOT NULL,
                CHECK (plan_protocol = 'webauthn-transition-v1'),
                CHECK (operation IN ('webauthn.registration.finalize', 'webauthn.trust.stage', 'webauthn.trust.complete')),
                CHECK (retained_at_epoch_ns BETWEEN 1 AND 9223372036854775807),
                CHECK (exact_envelope_byte_count BETWEEN 2 AND 67108864),
                CHECK (original_proof_byte_count BETWEEN 2 AND 67108864),
                CHECK (original_inputs_byte_count BETWEEN 2 AND 67108864),
                CHECK (evaluation_context_byte_count BETWEEN 2 AND 67108864),
                CHECK (exact_envelope_byte_count + original_proof_byte_count
                    + original_inputs_byte_count + evaluation_context_byte_count <= 67108864),
                CHECK (
                    length(exact_envelope_base64url) = (4 * exact_envelope_byte_count + 2) / 3
                    AND exact_envelope_base64url ~ '^[A-Za-z0-9_-]+$'
                    AND length(original_proof_base64url) = (4 * original_proof_byte_count + 2) / 3
                    AND original_proof_base64url ~ '^[A-Za-z0-9_-]+$'
                    AND length(original_inputs_base64url) = (4 * original_inputs_byte_count + 2) / 3
                    AND original_inputs_base64url ~ '^[A-Za-z0-9_-]+$'
                    AND length(evaluation_context_base64url) = (4 * evaluation_context_byte_count + 2) / 3
                    AND evaluation_context_base64url ~ '^[A-Za-z0-9_-]+$'
                ),
                CHECK (
                    exact_envelope_byte_count % 3 = 0
                    OR (exact_envelope_byte_count % 3 = 1
                        AND substr(exact_envelope_base64url, length(exact_envelope_base64url), 1) IN ('A', 'Q', 'g', 'w'))
                    OR (exact_envelope_byte_count % 3 = 2
                        AND substr(exact_envelope_base64url, length(exact_envelope_base64url), 1) IN
                            ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8'))
                ),
                CHECK (
                    original_proof_byte_count % 3 = 0
                    OR (original_proof_byte_count % 3 = 1
                        AND substr(original_proof_base64url, length(original_proof_base64url), 1) IN ('A', 'Q', 'g', 'w'))
                    OR (original_proof_byte_count % 3 = 2
                        AND substr(original_proof_base64url, length(original_proof_base64url), 1) IN
                            ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8'))
                ),
                CHECK (
                    original_inputs_byte_count % 3 = 0
                    OR (original_inputs_byte_count % 3 = 1
                        AND substr(original_inputs_base64url, length(original_inputs_base64url), 1) IN ('A', 'Q', 'g', 'w'))
                    OR (original_inputs_byte_count % 3 = 2
                        AND substr(original_inputs_base64url, length(original_inputs_base64url), 1) IN
                            ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8'))
                ),
                CHECK (
                    evaluation_context_byte_count % 3 = 0
                    OR (evaluation_context_byte_count % 3 = 1
                        AND substr(evaluation_context_base64url, length(evaluation_context_base64url), 1) IN ('A', 'Q', 'g', 'w'))
                    OR (evaluation_context_byte_count % 3 = 2
                        AND substr(evaluation_context_base64url, length(evaluation_context_base64url), 1) IN
                            ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8'))
                ),
                CHECK (
                    retained_record_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND operation_id ~ '^sha256:[0-9a-f]{64}$'
                    AND request_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND configuration_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND plan_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND exact_envelope_bytes_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND original_proof_bytes_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND original_inputs_bytes_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND evaluation_context_bytes_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND planner_key_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND operation_key_digest ~ '^sha256:[0-9a-f]{64}$'
                ),
                CHECK (source_revision = 'serverware.policyCandidateAuthoritySource/2026-07-30.254')
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_revocation_writer_requests (
                intent_envelope_id TEXT PRIMARY KEY,
                relay_envelope_id TEXT NOT NULL UNIQUE,
                execution_envelope_id TEXT NOT NULL UNIQUE,
                planner_transaction_id TEXT NOT NULL,
                plan_protocol TEXT NOT NULL,
                retained_record_digest TEXT NOT NULL,
                configuration_digest TEXT NOT NULL,
                generation_sequence BIGINT NOT NULL,
                generation_digest TEXT NOT NULL,
                exact_intent_base64url TEXT NOT NULL,
                exact_intent_bytes_digest TEXT NOT NULL,
                exact_intent_byte_count BIGINT NOT NULL,
                exact_relay_base64url TEXT NOT NULL,
                exact_relay_bytes_digest TEXT NOT NULL,
                exact_relay_byte_count BIGINT NOT NULL,
                historical_expectations_base64url TEXT NOT NULL,
                historical_expectations_bytes_digest TEXT NOT NULL,
                historical_expectations_byte_count BIGINT NOT NULL,
                planner_key_digest TEXT NOT NULL,
                verifier_key_digest TEXT NOT NULL,
                planned_at_epoch_ns BIGINT NOT NULL,
                source_revision TEXT NOT NULL,
                UNIQUE (intent_envelope_id, configuration_digest, generation_sequence,
                        generation_digest, source_revision),
                CONSTRAINT serverware_writer_request_plan_fk
                    FOREIGN KEY (planner_transaction_id, plan_protocol, retained_record_digest)
                    REFERENCES policy_authority_revocation_retained_plans
                        (planner_transaction_id, plan_protocol, retained_record_digest)
                    DEFERRABLE INITIALLY DEFERRED,
                CONSTRAINT serverware_writer_request_execution_fk
                    FOREIGN KEY (execution_envelope_id, planner_transaction_id)
                    REFERENCES policy_authority_execution_envelopes
                        (envelope_id, planner_transaction_id)
                    DEFERRABLE INITIALLY DEFERRED,
                CHECK (plan_protocol = 'revocation-v4'),
                CHECK (generation_sequence > 0 AND planned_at_epoch_ns > 0),
                CHECK (exact_intent_byte_count BETWEEN 2 AND 4194304),
                CHECK (exact_relay_byte_count BETWEEN 2 AND 4194304),
                CHECK (historical_expectations_byte_count BETWEEN 2 AND 67108864),
                CHECK (
                    length(exact_intent_base64url) = (4 * exact_intent_byte_count + 2) / 3
                    AND exact_intent_base64url ~ '^[A-Za-z0-9_-]+$'
                    AND length(exact_relay_base64url) = (4 * exact_relay_byte_count + 2) / 3
                    AND exact_relay_base64url ~ '^[A-Za-z0-9_-]+$'
                    AND length(historical_expectations_base64url) = (4 * historical_expectations_byte_count + 2) / 3
                    AND historical_expectations_base64url ~ '^[A-Za-z0-9_-]+$'
                ),
                CHECK (
                    exact_intent_byte_count % 3 = 0
                    OR (exact_intent_byte_count % 3 = 1 AND substr(exact_intent_base64url, length(exact_intent_base64url), 1) IN ('A','Q','g','w'))
                    OR (exact_intent_byte_count % 3 = 2 AND substr(exact_intent_base64url, length(exact_intent_base64url), 1) IN ('A','E','I','M','Q','U','Y','c','g','k','o','s','w','0','4','8'))
                ),
                CHECK (
                    exact_relay_byte_count % 3 = 0
                    OR (exact_relay_byte_count % 3 = 1 AND substr(exact_relay_base64url, length(exact_relay_base64url), 1) IN ('A','Q','g','w'))
                    OR (exact_relay_byte_count % 3 = 2 AND substr(exact_relay_base64url, length(exact_relay_base64url), 1) IN ('A','E','I','M','Q','U','Y','c','g','k','o','s','w','0','4','8'))
                ),
                CHECK (
                    historical_expectations_byte_count % 3 = 0
                    OR (historical_expectations_byte_count % 3 = 1 AND substr(historical_expectations_base64url, length(historical_expectations_base64url), 1) IN ('A','Q','g','w'))
                    OR (historical_expectations_byte_count % 3 = 2 AND substr(historical_expectations_base64url, length(historical_expectations_base64url), 1) IN ('A','E','I','M','Q','U','Y','c','g','k','o','s','w','0','4','8'))
                ),
                CHECK (intent_envelope_id ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (relay_envelope_id ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (execution_envelope_id ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (planner_transaction_id ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (retained_record_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (configuration_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (generation_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (exact_intent_bytes_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (exact_relay_bytes_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (historical_expectations_bytes_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (planner_key_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (verifier_key_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (source_revision = 'serverware.policyCandidateAuthoritySource/2026-07-30.254')
            );
        CREATE TABLE IF NOT EXISTS
            policy_authority_revocation_writer_acknowledgments (
                ack_envelope_id TEXT PRIMARY KEY,
                intent_envelope_id TEXT NOT NULL UNIQUE,
                configuration_digest TEXT NOT NULL,
                generation_sequence BIGINT NOT NULL,
                generation_digest TEXT NOT NULL,
                writer_response_spki_digest TEXT NOT NULL,
                exact_ack_base64url TEXT NOT NULL,
                exact_ack_bytes_digest TEXT NOT NULL,
                exact_ack_byte_count BIGINT NOT NULL,
                source_revision TEXT NOT NULL,
                CONSTRAINT serverware_writer_ack_request_fk
                    FOREIGN KEY (intent_envelope_id, configuration_digest, generation_sequence,
                                 generation_digest, source_revision)
                    REFERENCES policy_authority_revocation_writer_requests
                        (intent_envelope_id, configuration_digest, generation_sequence,
                         generation_digest, source_revision)
                    DEFERRABLE INITIALLY DEFERRED,
                CHECK (generation_sequence > 0),
                CHECK (exact_ack_byte_count BETWEEN 2 AND 16384),
                CHECK (
                    length(exact_ack_base64url) = (4 * exact_ack_byte_count + 2) / 3
                    AND exact_ack_base64url ~ '^[A-Za-z0-9_-]+$'
                ),
                CHECK (
                    exact_ack_byte_count % 3 = 0
                    OR (exact_ack_byte_count % 3 = 1 AND substr(exact_ack_base64url, length(exact_ack_base64url), 1) IN ('A','Q','g','w'))
                    OR (exact_ack_byte_count % 3 = 2 AND substr(exact_ack_base64url, length(exact_ack_base64url), 1) IN ('A','E','I','M','Q','U','Y','c','g','k','o','s','w','0','4','8'))
                ),
                CHECK (ack_envelope_id ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (intent_envelope_id ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (configuration_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (generation_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (writer_response_spki_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (exact_ack_bytes_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (source_revision = 'serverware.policyCandidateAuthoritySource/2026-07-30.254')
            );
        CREATE TABLE IF NOT EXISTS
            policy_authority_revocation_retained_capabilities (
                capability_id TEXT PRIMARY KEY,
                capability_protocol TEXT NOT NULL,
                capability_record_digest TEXT NOT NULL,
                planner_transaction_id TEXT NOT NULL,
                plan_protocol TEXT NOT NULL,
                retained_record_digest TEXT NOT NULL,
                execution_envelope_id TEXT NOT NULL,
                capability_digest TEXT NOT NULL,
                root_transition_digest TEXT NOT NULL,
                authority_snapshot_digest TEXT NOT NULL,
                exact_request_bytes_digest TEXT NOT NULL,
                exact_capability_base64url TEXT NOT NULL,
                exact_capability_bytes_digest TEXT NOT NULL,
                exact_capability_byte_count BIGINT NOT NULL,
                signer_key_digest TEXT NOT NULL,
                witness_key_digest TEXT NOT NULL,
                exact_witness_request_base64url TEXT NOT NULL,
                exact_witness_request_bytes_digest TEXT NOT NULL,
                exact_witness_request_byte_count BIGINT NOT NULL,
                source_revision TEXT NOT NULL,
                UNIQUE (capability_id, capability_protocol, capability_record_digest,
                        planner_transaction_id, execution_envelope_id),
                CONSTRAINT serverware_revocation_capability_parent_fk
                    FOREIGN KEY (capability_id, capability_protocol, capability_record_digest,
                                 planner_transaction_id, execution_envelope_id)
                    REFERENCES policy_authority_writer_capabilities
                        (capability_id, capability_protocol, capability_record_digest,
                         planner_transaction_id, envelope_id)
                    DEFERRABLE INITIALLY DEFERRED,
                CONSTRAINT serverware_revocation_capability_plan_fk
                    FOREIGN KEY (planner_transaction_id, plan_protocol, retained_record_digest)
                    REFERENCES policy_authority_revocation_retained_plans
                        (planner_transaction_id, plan_protocol, retained_record_digest)
                    DEFERRABLE INITIALLY DEFERRED,
                CONSTRAINT serverware_revocation_capability_envelope_fk
                    FOREIGN KEY (execution_envelope_id)
                    REFERENCES policy_authority_execution_envelopes (envelope_id)
                    DEFERRABLE INITIALLY DEFERRED,
                CHECK (capability_protocol = 'revocation-v4' AND plan_protocol = 'revocation-v4'),
                CHECK (exact_capability_byte_count BETWEEN 2 AND 4194304),
                CHECK (exact_witness_request_byte_count BETWEEN 2 AND 65536),
                CHECK (
                    length(exact_capability_base64url) = (4 * exact_capability_byte_count + 2) / 3
                    AND exact_capability_base64url ~ '^[A-Za-z0-9_-]+$'
                    AND length(exact_witness_request_base64url) = (4 * exact_witness_request_byte_count + 2) / 3
                    AND exact_witness_request_base64url ~ '^[A-Za-z0-9_-]+$'
                ),
                CHECK (
                    exact_capability_byte_count % 3 = 0
                    OR (exact_capability_byte_count % 3 = 1
                        AND substr(exact_capability_base64url, length(exact_capability_base64url), 1) IN ('A', 'Q', 'g', 'w'))
                    OR (exact_capability_byte_count % 3 = 2
                        AND substr(exact_capability_base64url, length(exact_capability_base64url), 1) IN
                            ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8'))
                ),
                CHECK (
                    exact_witness_request_byte_count % 3 = 0
                    OR (exact_witness_request_byte_count % 3 = 1
                        AND substr(exact_witness_request_base64url, length(exact_witness_request_base64url), 1) IN ('A', 'Q', 'g', 'w'))
                    OR (exact_witness_request_byte_count % 3 = 2
                        AND substr(exact_witness_request_base64url, length(exact_witness_request_base64url), 1) IN
                            ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8'))
                ),
                CHECK (
                    capability_id ~ '^sha256:[0-9a-f]{64}$'
                    AND capability_record_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND planner_transaction_id ~ '^sha256:[0-9a-f]{64}$'
                    AND retained_record_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND execution_envelope_id ~ '^sha256:[0-9a-f]{64}$'
                    AND capability_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND root_transition_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND authority_snapshot_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND exact_request_bytes_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND exact_capability_bytes_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND signer_key_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND witness_key_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND exact_witness_request_bytes_digest ~ '^sha256:[0-9a-f]{64}$'
                ),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_bounded_aggregate_states (
                aggregate_id TEXT PRIMARY KEY,
                aggregate_kind TEXT NOT NULL,
                partition_digest TEXT NOT NULL,
                revision BIGINT NOT NULL,
                live_count BIGINT NOT NULL,
                active_count BIGINT NOT NULL,
                capacity_limit BIGINT NOT NULL,
                reserved_units_json TEXT NOT NULL,
                committed_units_json TEXT NOT NULL,
                next_sequence BIGINT NOT NULL,
                minimum_expiry_epoch_ns BIGINT,
                expiry_index_root_digest TEXT NOT NULL,
                work_page_id TEXT,
                state_json TEXT NOT NULL,
                state_digest TEXT NOT NULL,
                updated_at_epoch_ns BIGINT NOT NULL,
                source_revision TEXT NOT NULL,
                CHECK (length(aggregate_id) BETWEEN 1 AND 256),
                CHECK (length(aggregate_kind) BETWEEN 1 AND 128),
                CHECK (
                    aggregate_id =
                        aggregate_kind || ':' || partition_digest
                ),
                CHECK (
                    partition_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND expiry_index_root_digest
                        ~ '^sha256:[0-9a-f]{64}$'
                    AND state_digest ~ '^sha256:[0-9a-f]{64}$'
                ),
                CHECK (revision > 0),
                CHECK (live_count >= 0),
                CHECK (active_count >= 0),
                CHECK (active_count <= live_count),
                CHECK (capacity_limit >= 0),
                CHECK (live_count <= capacity_limit),
                CHECK (next_sequence >= 0),
                CHECK (
                    minimum_expiry_epoch_ns IS NULL
                    OR minimum_expiry_epoch_ns >= 0
                ),
                CHECK (length(reserved_units_json) BETWEEN 1 AND 4194304),
                CHECK (length(committed_units_json) BETWEEN 1 AND 4194304),
                CHECK (length(state_json) BETWEEN 2 AND 4194304),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_exact_pages (
                page_digest TEXT PRIMARY KEY,
                relation_name TEXT NOT NULL,
                predicate_digest TEXT NOT NULL,
                ordering_digest TEXT NOT NULL,
                relation_root_digest TEXT NOT NULL,
                relation_revision BIGINT NOT NULL,
                page_sequence BIGINT NOT NULL,
                row_count BIGINT NOT NULL,
                first_key_json TEXT,
                last_key_json TEXT,
                rows_digest TEXT NOT NULL,
                continuation_page_digest TEXT,
                terminal BIGINT NOT NULL,
                proof_json TEXT NOT NULL,
                proof_digest TEXT NOT NULL,
                created_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                source_revision TEXT NOT NULL,
                CHECK (length(relation_name) BETWEEN 1 AND 128),
                CHECK (
                    page_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND predicate_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND ordering_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND relation_root_digest
                        ~ '^sha256:[0-9a-f]{64}$'
                    AND rows_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND proof_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND (
                        continuation_page_digest IS NULL
                        OR continuation_page_digest
                            ~ '^sha256:[0-9a-f]{64}$'
                    )
                ),
                CHECK (relation_revision > 0),
                CHECK (page_sequence > 0),
                CHECK (row_count BETWEEN 0 AND 64),
                CHECK (terminal IN (0, 1)),
                CHECK (
                    (row_count = 0
                        AND first_key_json IS NULL
                        AND last_key_json IS NULL)
                    OR
                    (row_count > 0
                        AND first_key_json IS NOT NULL
                        AND last_key_json IS NOT NULL)
                ),
                CHECK (
                    (terminal = 1 AND continuation_page_digest IS NULL)
                    OR
                    (terminal = 0 AND continuation_page_digest IS NOT NULL)
                ),
                CHECK (length(proof_json) BETWEEN 2 AND 4194304),
                CHECK (created_at_epoch_ns >= 0),
                CHECK (expires_at_epoch_ns > created_at_epoch_ns),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_work_pages (
                page_id TEXT PRIMARY KEY,
                aggregate_id TEXT NOT NULL,
                page_kind TEXT NOT NULL,
                page_sequence BIGINT NOT NULL,
                item_count BIGINT NOT NULL,
                items_json TEXT NOT NULL,
                items_digest TEXT NOT NULL,
                complete_through_epoch_ns BIGINT NOT NULL,
                continuation_page_id TEXT,
                status TEXT NOT NULL,
                created_at_epoch_ns BIGINT NOT NULL,
                consumed_at_epoch_ns BIGINT,
                source_revision TEXT NOT NULL,
                UNIQUE (aggregate_id, page_kind, page_sequence),
                CHECK (length(page_id) BETWEEN 1 AND 256),
                CHECK (length(aggregate_id) BETWEEN 1 AND 256),
                CHECK (length(page_kind) BETWEEN 1 AND 128),
                CHECK (items_digest ~ '^sha256:[0-9a-f]{64}$'),
                CHECK (page_sequence > 0),
                CHECK (item_count BETWEEN 0 AND 64),
                CHECK (length(items_json) BETWEEN 2 AND 4194304),
                CHECK (complete_through_epoch_ns >= 0),
                CHECK (status IN ('pending', 'consumed')),
                CHECK (
                    (status = 'pending' AND consumed_at_epoch_ns IS NULL)
                    OR
                    (status = 'consumed'
                        AND consumed_at_epoch_ns IS NOT NULL)
                ),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_tombstones (
                tombstone_id TEXT PRIMARY KEY,
                source_table TEXT NOT NULL,
                source_key_json TEXT NOT NULL,
                source_key_digest TEXT NOT NULL,
                source_row_digest TEXT NOT NULL,
                operation TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                reason TEXT NOT NULL,
                deleted_at_epoch_ns BIGINT NOT NULL,
                source_revision TEXT NOT NULL,
                UNIQUE (source_table, source_key_digest, operation_id),
                CHECK (length(source_table) BETWEEN 1 AND 128),
                CHECK (length(source_key_json) BETWEEN 2 AND 4194304),
                CHECK (length(operation) BETWEEN 1 AND 128),
                CHECK (length(operation_id) BETWEEN 1 AND 256),
                CHECK (length(reason) BETWEEN 1 AND 256),
                CHECK (
                    source_key_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND source_row_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND request_digest ~ '^sha256:[0-9a-f]{64}$'
                ),
                CHECK (deleted_at_epoch_ns >= 0),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_opaque_values (
                opaque_id TEXT PRIMARY KEY,
                value_kind TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                key_id TEXT NOT NULL,
                ciphertext_base64url TEXT NOT NULL,
                ciphertext_digest TEXT NOT NULL,
                binding_digest TEXT NOT NULL,
                producer_evidence_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT,
                consumed_at_epoch_ns BIGINT,
                source_revision TEXT NOT NULL,
                CHECK (length(opaque_id) BETWEEN 1 AND 256),
                CHECK (length(value_kind) BETWEEN 1 AND 128),
                CHECK (length(algorithm) BETWEEN 1 AND 128),
                CHECK (length(key_id) BETWEEN 1 AND 256),
                CHECK (
                    ciphertext_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND binding_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND producer_evidence_digest
                        ~ '^sha256:[0-9a-f]{64}$'
                ),
                CHECK (
                    length(ciphertext_base64url)
                    BETWEEN 1 AND 4194304
                ),
                CHECK (status IN ('active', 'consumed', 'revoked')),
                CHECK (created_at_epoch_ns >= 0),
                CHECK (
                    expires_at_epoch_ns IS NULL
                    OR expires_at_epoch_ns > created_at_epoch_ns
                ),
                CHECK (
                    (status = 'active' AND consumed_at_epoch_ns IS NULL)
                    OR status IN ('consumed', 'revoked')
                ),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_external_evidence_receipts (
                evidence_digest TEXT PRIMARY KEY,
                evidence_type TEXT NOT NULL,
                statement_json TEXT NOT NULL,
                statement_digest TEXT NOT NULL,
                verifier_identity_digest TEXT NOT NULL,
                verifier_measurement_digest TEXT NOT NULL,
                verifier_attestation_receipt_digest TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signature_base64url TEXT NOT NULL,
                signature_digest TEXT NOT NULL,
                binding_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                verified_at_epoch_ns BIGINT NOT NULL,
                expires_at_epoch_ns BIGINT NOT NULL,
                consumed_operation_id TEXT,
                consumed_at_epoch_ns BIGINT,
                source_revision TEXT NOT NULL,
                CHECK (length(evidence_type) BETWEEN 1 AND 128),
                CHECK (
                    evidence_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND statement_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND verifier_identity_digest
                        ~ '^sha256:[0-9a-f]{64}$'
                    AND verifier_measurement_digest
                        ~ '^sha256:[0-9a-f]{64}$'
                    AND verifier_attestation_receipt_digest
                        ~ '^sha256:[0-9a-f]{64}$'
                    AND signature_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND binding_digest ~ '^sha256:[0-9a-f]{64}$'
                ),
                CHECK (length(statement_json) BETWEEN 2 AND 4194304),
                CHECK (signature_algorithm = 'Ed25519'),
                CHECK (length(signature_base64url) BETWEEN 1 AND 4194304),
                CHECK (status IN ('verified', 'consumed', 'revoked')),
                CHECK (verified_at_epoch_ns >= 0),
                CHECK (expires_at_epoch_ns > verified_at_epoch_ns),
                CHECK (
                    (status = 'verified'
                        AND consumed_operation_id IS NULL
                        AND consumed_at_epoch_ns IS NULL)
                    OR
                    (status = 'consumed'
                        AND consumed_operation_id IS NOT NULL
                        AND consumed_at_epoch_ns IS NOT NULL)
                    OR status = 'revoked'
                ),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_secondary_index_heads (
                index_id TEXT PRIMARY KEY,
                relation_name TEXT NOT NULL,
                index_name TEXT NOT NULL,
                key_columns_json TEXT NOT NULL,
                key_columns_digest TEXT NOT NULL,
                root_digest TEXT NOT NULL,
                revision BIGINT NOT NULL,
                row_count BIGINT NOT NULL,
                high_water_key_json TEXT,
                high_water_key_digest TEXT,
                updated_at_epoch_ns BIGINT NOT NULL,
                source_revision TEXT NOT NULL,
                UNIQUE (relation_name, index_name),
                CHECK (length(index_id) BETWEEN 1 AND 256),
                CHECK (length(relation_name) BETWEEN 1 AND 128),
                CHECK (length(index_name) BETWEEN 1 AND 128),
                CHECK (length(key_columns_json) BETWEEN 2 AND 65536),
                CHECK (
                    key_columns_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND root_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND (
                        high_water_key_digest IS NULL
                        OR high_water_key_digest
                            ~ '^sha256:[0-9a-f]{64}$'
                    )
                ),
                CHECK (revision > 0),
                CHECK (row_count >= 0),
                CHECK (
                    (high_water_key_json IS NULL
                        AND high_water_key_digest IS NULL)
                    OR
                    (high_water_key_json IS NOT NULL
                        AND high_water_key_digest IS NOT NULL)
                ),
                CHECK (updated_at_epoch_ns >= 0),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );

        CREATE TABLE IF NOT EXISTS policy_authority_continuations (
            continuation_digest TEXT PRIMARY KEY,
            operation TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            page_kind TEXT NOT NULL,
            page_ordinal BIGINT NOT NULL,
            source_relation TEXT NOT NULL,
            source_root_digest TEXT NOT NULL,
            source_revision_number BIGINT NOT NULL,
            next_key_json TEXT NOT NULL,
            next_key_digest TEXT NOT NULL,
            accumulated_state_digest TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at_epoch_ns BIGINT NOT NULL,
            expires_at_epoch_ns BIGINT NOT NULL,
            completed_at_epoch_ns BIGINT,
            source_revision TEXT NOT NULL,
            UNIQUE (operation_id, page_kind, page_ordinal),
            CHECK (length(operation) BETWEEN 1 AND 128),
            CHECK (length(operation_id) BETWEEN 1 AND 256),
            CHECK (length(page_kind) BETWEEN 1 AND 128),
            CHECK (length(source_relation) BETWEEN 1 AND 128),
            CHECK (length(next_key_json) BETWEEN 2 AND 4194304),
            CHECK (
                request_digest ~ '^sha256:[0-9a-f]{64}$'
                AND source_root_digest ~ '^sha256:[0-9a-f]{64}$'
                AND next_key_digest ~ '^sha256:[0-9a-f]{64}$'
                AND accumulated_state_digest
                    ~ '^sha256:[0-9a-f]{64}$'
            ),
            CHECK (page_ordinal > 0),
            CHECK (source_revision_number > 0),
            CHECK (status IN ('pending', 'completed', 'cancelled')),
            CHECK (created_at_epoch_ns >= 0),
            CHECK (expires_at_epoch_ns > created_at_epoch_ns),
            CHECK (
                (status = 'pending' AND completed_at_epoch_ns IS NULL)
                OR
                (status IN ('completed', 'cancelled')
                    AND completed_at_epoch_ns IS NOT NULL)
            ),
            CHECK (
                source_revision =
                'serverware.policyCandidateAuthoritySource/2026-07-30.254'
            )
        );

        CREATE TABLE IF NOT EXISTS policy_authority_sealed_values (
            sealed_value_id TEXT PRIMARY KEY,
            value_kind TEXT NOT NULL,
            target_table TEXT NOT NULL,
            target_column TEXT NOT NULL,
            target_row_key_digest TEXT NOT NULL,
            purpose TEXT NOT NULL,
            plaintext_digest TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            key_id TEXT NOT NULL,
            key_generation BIGINT NOT NULL,
            nonce_base64url TEXT NOT NULL,
            ciphertext_base64url TEXT NOT NULL,
            ciphertext_digest TEXT NOT NULL,
            request_id TEXT NOT NULL,
            binding_digest TEXT NOT NULL,
            producer_evidence_digest TEXT NOT NULL,
            status TEXT NOT NULL,
            issued_at_epoch_ns BIGINT NOT NULL,
            expires_at_epoch_ns BIGINT NOT NULL,
            consumed_at_epoch_ns BIGINT,
            source_revision TEXT NOT NULL,
            UNIQUE (
                target_table,
                target_column,
                target_row_key_digest,
                purpose,
                request_id
            ),
            UNIQUE (binding_digest),
            CHECK (length(sealed_value_id) BETWEEN 1 AND 256),
            CHECK (length(value_kind) BETWEEN 1 AND 128),
            CHECK (length(target_table) BETWEEN 1 AND 128),
            CHECK (length(target_column) BETWEEN 1 AND 128),
            CHECK (length(purpose) BETWEEN 1 AND 256),
            CHECK (length(algorithm) BETWEEN 1 AND 128),
            CHECK (length(key_id) BETWEEN 1 AND 256),
            CHECK (length(request_id) BETWEEN 1 AND 256),
            CHECK (
                target_row_key_digest ~ '^sha256:[0-9a-f]{64}$'
                AND plaintext_digest ~ '^sha256:[0-9a-f]{64}$'
                AND ciphertext_digest ~ '^sha256:[0-9a-f]{64}$'
                AND binding_digest ~ '^sha256:[0-9a-f]{64}$'
                AND producer_evidence_digest
                    ~ '^sha256:[0-9a-f]{64}$'
            ),
            CHECK (key_generation > 0),
            CHECK (length(nonce_base64url) BETWEEN 1 AND 1024),
            CHECK (
                length(ciphertext_base64url)
                BETWEEN 1 AND 4194304
            ),
            CHECK (status IN ('active', 'consumed', 'revoked')),
            CHECK (issued_at_epoch_ns >= 0),
            CHECK (expires_at_epoch_ns > issued_at_epoch_ns),
            CHECK (
                (status = 'active' AND consumed_at_epoch_ns IS NULL)
                OR
                (status = 'consumed' AND consumed_at_epoch_ns IS NOT NULL)
                OR status = 'revoked'
            ),
            CHECK (
                source_revision =
                'serverware.policyCandidateAuthoritySource/2026-07-30.254'
            )
        );

        CREATE TABLE IF NOT EXISTS
            policy_authority_activation_evidence_bindings (
                preparation_digest TEXT PRIMARY KEY,
                activation_attempt_id TEXT NOT NULL UNIQUE,
                evidence_digest TEXT NOT NULL UNIQUE,
                binding_digest TEXT NOT NULL UNIQUE,
                evidence_chain_digest TEXT NOT NULL UNIQUE,
                generation_publication_envelope_digest TEXT NOT NULL,
                activation_publication_envelope_digest TEXT NOT NULL,
                runtime_verifier_envelope_digest TEXT NOT NULL,
                generation_id_digest TEXT NOT NULL,
                publication_request_id TEXT NOT NULL UNIQUE,
                replay_id TEXT NOT NULL UNIQUE,
                publication_revision BIGINT NOT NULL,
                consumed_operation_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                created_at_epoch_ns BIGINT NOT NULL,
                finalized_at_epoch_ns BIGINT,
                source_revision TEXT NOT NULL,
                UNIQUE (
                    evidence_digest,
                    binding_digest,
                    consumed_operation_id
                ),
                CHECK (
                    evidence_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND binding_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND evidence_chain_digest
                        ~ '^sha256:[0-9a-f]{64}$'
                    AND generation_publication_envelope_digest
                        ~ '^sha256:[0-9a-f]{64}$'
                    AND activation_publication_envelope_digest
                        ~ '^sha256:[0-9a-f]{64}$'
                    AND runtime_verifier_envelope_digest
                        ~ '^sha256:[0-9a-f]{64}$'
                    AND generation_id_digest
                        ~ '^sha256:[0-9a-f]{64}$'
                ),
                CHECK (length(preparation_digest) BETWEEN 1 AND 256),
                CHECK (length(activation_attempt_id) BETWEEN 1 AND 256),
                CHECK (length(publication_request_id) BETWEEN 1 AND 256),
                CHECK (length(replay_id) BETWEEN 1 AND 256),
                CHECK (length(consumed_operation_id) BETWEEN 1 AND 256),
                CHECK (publication_revision > 0),
                CHECK (
                    status IN ('prepared', 'finalized', 'aborted')
                ),
                CHECK (created_at_epoch_ns >= 0),
                CHECK (
                    (status = 'prepared' AND finalized_at_epoch_ns IS NULL)
                    OR
                    (status IN ('finalized', 'aborted')
                        AND finalized_at_epoch_ns IS NOT NULL)
                ),
                CHECK (
                    source_revision =
                    'serverware.policyCandidateAuthoritySource/2026-07-30.254'
                )
            );
    """.replace(
        "__MAX_PLAN_SELECTED_BYTES__", str(authority_contract.MAX_PLAN_SELECTED_BYTES)
    ).replace(
        "__MAX_PLAN_WORK_UNITS__", str(authority_contract.MAX_PLAN_WORK_UNITS)
    )
