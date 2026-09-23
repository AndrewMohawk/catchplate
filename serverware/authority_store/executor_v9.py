from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Mapping
from typing import Any

from serverware import authority_contract
from serverware import authority_transition_registry
from serverware.authority_root_transition import (
    primary_root_transition_digest,
    validate_primary_root_transition,
)
from serverware.authority_store.mutation_sql import (
    apply_mutation_sql,
    closed_record_sql,
    locked_primary_key_row_sql,
    selected_row_matches_sql,
)
from serverware.authority_store.webauthn_trust_sql import (
    locked_webauthn_trust_projection,
)
from serverware.authority_store.root_transition_sql import (
    assert_root_transition_after_sql,
    assert_root_transition_before_sql,
    assert_root_transition_payload_sql,
    assert_root_transition_replay_sql,
    load_root_transition_sql,
    root_transition_declarations_sql,
)

_DB_GLOBALS: Mapping[str, Any] | None = None
_DIGEST_PATTERN = "sha256:" + "0" * 64


def bind_db_globals(namespace: Mapping[str, Any]) -> None:
    global _DB_GLOBALS
    _DB_GLOBALS = namespace


def _db_value(name: str) -> Any:
    if _DB_GLOBALS is None or name not in _DB_GLOBALS:
        raise RuntimeError(f"database facade binding is missing {name}")
    return _DB_GLOBALS[name]


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _digest(domain: str, *payloads: bytes) -> str:
    hasher = hashlib.sha256()
    encoded_domain = domain.encode("ascii")
    hasher.update(encoded_domain)
    hasher.update(b"\x00")
    for payload in payloads:
        hasher.update(len(payload).to_bytes(8, "big"))
        hasher.update(payload)
    return "sha256:" + hasher.hexdigest()


def _b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _decode_b64url(value: Any, *, label: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or any(
            character not in
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in value
        )
    ):
        raise ValueError(f"{label} is not canonical base64url")
    payload = base64.urlsafe_b64decode(
        value + "=" * ((4 - len(value) % 4) % 4)
    )
    if _b64url(payload) != value:
        raise ValueError(f"{label} base64url encoding is not exact")
    return payload


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _verify_pinned_verifier_envelope(
    envelope: Mapping[str, Any],
    *,
    domain: str,
    receipt_digest_field: str,
) -> None:
    signature = _decode_b64url(
        envelope.get("verifierSignatureBase64url"),
        label="measured verifier signature",
    )
    if len(signature) != 64:
        raise ValueError("measured verifier signature length is invalid")
    unsigned = dict(envelope)
    unsigned.pop("verifierSignatureBase64url", None)
    unsigned.pop("verifierSignatureDigest", None)
    receipt_digest = unsigned.pop(receipt_digest_field, None)
    statement_digest = _digest(
        domain,
        _canonical(unsigned).encode("ascii"),
    )
    if (
        receipt_digest != statement_digest
        or envelope.get("verifierSignatureDigest")
            != "sha256:" + hashlib.sha256(signature).hexdigest()
    ):
        raise ValueError("measured verifier receipt digest is not exact")
    invalid_signature = _db_value("InvalidSignature")
    try:
        _db_value("Ed25519PublicKey").from_public_bytes(
            _db_value("_policy_authority_verifier_public_key")()
        ).verify(signature, statement_digest.encode("ascii"))
    except invalid_signature as exc:
        raise ValueError(
            "measured verifier envelope signature is invalid"
        ) from exc


def _operation_id(operation: str, request_digest: str) -> str:
    return _digest(
        "serverware.policyAuthorityOperation/v2",
        operation.encode("utf-8"),
        request_digest.encode("utf-8"),
    )


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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
                )
            );

        CREATE TABLE IF NOT EXISTS
            policy_authority_planner_transactions (
                planner_transaction_id TEXT PRIMARY KEY,
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
                CHECK (
                    status IN ('reserved', 'planned', 'consumed', 'failed')
                ),
                CHECK (
                    length(selected_business_rows_json)
                    BETWEEN 2 AND 4194304
                ),
                CHECK (length(mutation_plan_json) BETWEEN 2 AND 67108864),
                CHECK (work_units BETWEEN 1 AND 4096),
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                'serverware.policyCandidateAuthoritySource/2026-07-30.24'
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
                    'serverware.policyCandidateAuthoritySource/2026-07-30.24'
                )
            );
    """


def install_authority_v9_executor(
    conn: Any,
    *,
    namespace: str,
    source_revision: str,
    operation_manifest_digest: str,
) -> None:
    if source_revision != authority_contract.SOURCE_REVISION:
        raise RuntimeError("authority v9 executor source revision is not exact")
    operation_handlers = _canonical(
        {
            operation: spec["handler"]
            for operation, spec in authority_contract.OPERATIONS.items()
            if operation
                in authority_transition_registry.PLANNABLE_OPERATIONS
        }
    ).replace("'", "''")
    assertion_requirements = _canonical(
        {
            operation: bool(spec["assertionRequired"])
            for operation, spec in authority_contract.OPERATIONS.items()
            if operation
                in authority_transition_registry.PLANNABLE_OPERATIONS
        }
    ).replace("'", "''")
    operation_manifest_counts = _canonical(
        {
            operation: len(
                set(spec["businessReads"]) | set(spec["businessWrites"])
            )
            for operation, spec in authority_contract.OPERATIONS.items()
            if operation
                in authority_transition_registry.PLANNABLE_OPERATIONS
        }
    ).replace("'", "''")
    operation_limits = _canonical(
        {
            operation: {
                "maximumMutations": int(spec["maximumMutations"]),
                "maximumQueryRows": int(spec["maximumQueryRows"]),
                "maximumWorkUnits": int(spec["maximumWorkUnits"]),
            }
            for operation, spec in authority_contract.OPERATIONS.items()
            if operation
                in authority_transition_registry.PLANNABLE_OPERATIONS
        }
    ).replace("'", "''")
    authorization_manifest_counts = _canonical(
        {
            operation: len(spec["authorizationReads"])
            for operation, spec in authority_contract.OPERATIONS.items()
            if operation
                in authority_transition_registry.PLANNABLE_OPERATIONS
        }
    ).replace("'", "''")
    authorization_read_sets = _canonical(
        {
            operation: list(spec["authorizationReads"])
            for operation, spec in authority_contract.OPERATIONS.items()
            if operation
                in authority_transition_registry.PLANNABLE_OPERATIONS
        }
    ).replace("'", "''")
    capability_issuer_role = str(
        _db_value("_METADATA_STORE_AUTHORITY_CAPABILITY_ISSUER_ROLE")
    ).replace("'", "''")
    wrapper_bodies = {
        operation: (
            f"""
            PERFORM pg_catalog.set_config(
                'serverware.policy_authority_expected_operation',
                '{operation}',
                true
            );
            RETURN {namespace}.serverware_policy_authority_execute_v9(
                supplied_capability_id,
                supplied_envelope_id,
                supplied_planner_transaction_id,
                supplied_exact_request_base64url,
                supplied_exact_result_base64url
            );
            """
            if operation
                in authority_transition_registry.PLANNABLE_OPERATIONS
            else
            """
            RAISE EXCEPTION
                'authority operation has no exact typed transition program';
            """
        )
        for operation in authority_contract.OPERATION_REGISTRY
    }
    wrapper_definitions = "\n".join(
        f"""
        CREATE OR REPLACE FUNCTION {namespace}.{function_name}(
            supplied_capability_id text,
            supplied_envelope_id text,
            supplied_planner_transaction_id text,
            supplied_exact_request_base64url text,
            supplied_exact_result_base64url text
        )
        RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        VOLATILE
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $serverware_operation_executor$
        BEGIN
            {wrapper_bodies[operation]}
        END;
        $serverware_operation_executor$;
        """
        for function_name, operation
        in authority_contract.EXECUTOR_FUNCTION_TO_OPERATION.items()
    )
    conn.execute(
        f"""
        DROP FUNCTION IF EXISTS {namespace}.
            serverware_policy_authority_issue_writer_capability(
                text, text, text, text
            );

        CREATE OR REPLACE FUNCTION {namespace}.
            serverware_policy_authority_issue_writer_capability(
                capability_json text,
                supplied_capability_digest text,
                supplied_issuer_measurement_digest text,
                supplied_issuer_attestation_receipt_digest text,
                supplied_issuer_credential_issuance_digest text
            )
        RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        VOLATILE
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $serverware_issue_writer_capability_v3$
        DECLARE
            capability_value pg_catalog.jsonb;
            reservation_value pg_catalog.jsonb;
            canonical_capability text;
            canonical_reservation text;
            computed_capability_digest text;
            computed_reservation_digest text;
            existing_capability record;
            existing_reservation record;
            inserted_count bigint;
        BEGIN
            IF session_user <> '{capability_issuer_role}'
                OR supplied_issuer_measurement_digest !~
                    '^sha256:[0-9a-f]{{64}}$'
                OR supplied_issuer_attestation_receipt_digest !~
                    '^sha256:[0-9a-f]{{64}}$'
                OR supplied_issuer_credential_issuance_digest !~
                    '^sha256:[0-9a-f]{{64}}$'
            THEN
                RAISE EXCEPTION
                    'writer capability v3 issuer identity is not exact';
            END IF;
            capability_value := capability_json::pg_catalog.jsonb;
            canonical_capability := {namespace}.
                serverware_policy_authority_wire_json(
                    capability_value
                );
            computed_capability_digest := {namespace}.
                serverware_policy_authority_domain_digest(
                    'serverware.policyAuthorityDatabaseCapability/v3',
                    canonical_capability
                );
            reservation_value :=
                capability_value->'witnessReservation';
            canonical_reservation := {namespace}.
                serverware_policy_authority_wire_json(
                    reservation_value
                );
            computed_reservation_digest := {namespace}.
                serverware_policy_authority_domain_digest(
                    'serverware.policyAuthorityReplayWitnessReceipt/v2',
                    canonical_reservation
                );
            IF canonical_capability IS DISTINCT FROM capability_json
                OR supplied_capability_digest IS DISTINCT FROM
                    computed_capability_digest
                OR pg_catalog.jsonb_typeof(capability_value) <> 'object'
                OR (
                    SELECT pg_catalog.count(*)
                    FROM pg_catalog.jsonb_object_keys(capability_value)
                ) <> 32
                OR NOT capability_value ?& ARRAY[
                    'schema', 'capabilityId', 'envelopeId',
                    'plannerTransactionId',
                    'authorizationProjectionDigest',
                    'selectedBusinessRowsDigest',
                    'mutationPlanDigest', 'expectedResultDigest',
                    'operation', 'operationId', 'handlerName',
                    'requestDigest', 'operationManifestDigest',
                    'queryManifestDigest', 'authorityRootSetDigest',
                    'authoritySnapshotDigest', 'approverPolicyDigest',
                    'webauthnReceipt', 'webauthnReceiptDigest',
                    'webauthnTrustHighWaterDigest',
                    'witnessReservation', 'witnessReservationDigest',
                    'witnessSequence', 'witnessHeadDigest',
                    'witnessPredecessorHeadDigest',
                    'deadlineMonotonicNs', 'deadlineEpochNs', 'fence',
                    'issuedMonotonicNs', 'issuedAtEpochNs',
                    'expiresAtEpochNs', 'issuerSessionIdentityDigest'
                ]
                OR capability_value->>'schema' <>
                    'serverware.policyAuthorityDatabaseCapability/v3'
                OR capability_value->>'operationManifestDigest' <>
                    '{operation_manifest_digest}'
                OR capability_value->>'handlerName' IS DISTINCT FROM
                    (
                        '{operation_handlers}'::pg_catalog.jsonb
                        ->> (capability_value->>'operation')
                    )
                OR capability_value->>'capabilityId' !~
                    '^sha256:[0-9a-f]{{64}}$'
                OR capability_value->>'envelopeId' !~
                    '^sha256:[0-9a-f]{{64}}$'
                OR capability_value->>'plannerTransactionId' !~
                    '^sha256:[0-9a-f]{{64}}$'
                OR capability_value->>'requestDigest' !~
                    '^sha256:[0-9a-f]{{64}}$'
                OR capability_value->>'witnessReservationDigest'
                    IS DISTINCT FROM computed_reservation_digest
                OR capability_value->>'witnessSequence'
                    IS DISTINCT FROM reservation_value->>'sequence'
                OR capability_value->>'witnessHeadDigest'
                    IS DISTINCT FROM reservation_value->>'headDigest'
                OR capability_value->'witnessPredecessorHeadDigest'
                    IS DISTINCT FROM
                        reservation_value->'predecessorHeadDigest'
                OR capability_value->>'fence'
                    IS DISTINCT FROM reservation_value->>'fence'
                OR capability_value->>'deadlineMonotonicNs'
                    IS DISTINCT FROM
                        reservation_value->>'deadlineMonotonicNs'
                OR reservation_value->>'schema' <>
                    'serverware.policyAuthorityReplayWitnessReceipt/v2'
                OR reservation_value->>'phase' NOT IN (
                    'reserve', 'webauthn-trust-publish'
                )
                OR reservation_value->>'operation' IS DISTINCT FROM
                    capability_value->>'operation'
                OR reservation_value->>'requestDigest' IS DISTINCT FROM
                    capability_value->>'requestDigest'
                OR reservation_value->>'capabilityId' IS DISTINCT FROM
                    capability_value->>'capabilityId'
                OR reservation_value->'resultDigest' <>
                    'null'::pg_catalog.jsonb
                OR reservation_value->'parentEnvelopeId' <>
                    'null'::pg_catalog.jsonb
                OR reservation_value->'predecessorReceiptDigest' <>
                    'null'::pg_catalog.jsonb
                OR reservation_value->>'envelopeId' !~
                    '^sha256:[0-9a-f]{{64}}$'
                OR reservation_value->>'canonicalRequestDigest' !~
                    '^sha256:[0-9a-f]{{64}}$'
                OR (capability_value->>'witnessSequence')::bigint < 1
                OR (capability_value->>'fence')::bigint < 1
                OR (capability_value->>'deadlineMonotonicNs')::bigint <=
                    (capability_value->>'issuedMonotonicNs')::bigint
                OR (capability_value->>'deadlineEpochNs')::bigint <=
                    (capability_value->>'issuedAtEpochNs')::bigint
                OR (capability_value->>'expiresAtEpochNs')::bigint <>
                    (capability_value->>'deadlineEpochNs')::bigint
            THEN
                RAISE EXCEPTION
                    'writer capability v3 or witness v2 is not closed';
            END IF;
            INSERT INTO {namespace}.
                policy_authority_external_witness_receipts (
                    witness_receipt_digest, witness_identity_digest,
                    witness_sequence, witness_head_digest,
                    predecessor_head_digest,
                    predecessor_receipt_digest,
                    log_predecessor_head_digest, phase, operation,
                    request_digest, capability_id, result_digest,
                    fence, receipt_json, recorded_at_epoch_ns
                )
            VALUES (
                computed_reservation_digest,
                reservation_value->>'witnessIdentityDigest',
                (reservation_value->>'sequence')::bigint,
                reservation_value->>'headDigest',
                reservation_value->>'predecessorHeadDigest',
                reservation_value->>'predecessorReceiptDigest',
                reservation_value->>'logPredecessorHeadDigest',
                reservation_value->>'phase',
                capability_value->>'operation',
                capability_value->>'requestDigest',
                capability_value->>'capabilityId', NULL,
                (capability_value->>'fence')::bigint,
                canonical_reservation,
                (reservation_value->>'issuedAtEpochNs')::bigint
            )
            ON CONFLICT (witness_receipt_digest) DO NOTHING;
            SELECT * INTO existing_reservation
            FROM {namespace}.policy_authority_external_witness_receipts
            WHERE witness_receipt_digest = computed_reservation_digest;
            IF NOT FOUND
                OR existing_reservation.receipt_json IS DISTINCT FROM
                    canonical_reservation
            THEN
                RAISE EXCEPTION
                    'writer witness v2 reservation was reused';
            END IF;
            SELECT * INTO existing_capability
            FROM {namespace}.policy_authority_writer_capabilities
            WHERE capability_id = capability_value->>'capabilityId'
            FOR UPDATE;
            IF FOUND THEN
                IF (
                    existing_capability.capability_digest IS DISTINCT FROM
                        computed_capability_digest
                    OR existing_capability.issuer_measurement_digest
                        IS DISTINCT FROM
                        supplied_issuer_measurement_digest
                    OR existing_capability.issuer_attestation_receipt_digest
                        IS DISTINCT FROM
                        supplied_issuer_attestation_receipt_digest
                    OR existing_capability.issuer_credential_issuance_digest
                        IS DISTINCT FROM
                        supplied_issuer_credential_issuance_digest
                )
                THEN
                    RAISE EXCEPTION
                        'writer capability v3 identity was reused';
                END IF;
                RETURN capability_value->>'capabilityId';
            END IF;
            INSERT INTO {namespace}.policy_authority_writer_capabilities (
                capability_id, capability_digest, envelope_id,
                operation, operation_id, handler_name, request_digest,
                operation_manifest_digest, query_manifest_digest,
                authority_root_set_digest, authority_snapshot_digest,
                approver_policy_digest, webauthn_receipt_json,
                webauthn_receipt_digest,
                webauthn_trust_high_water_digest,
                witness_reservation_digest, witness_sequence,
                witness_head_digest, deadline_monotonic_ns, fence,
                issued_monotonic_ns, issued_at_epoch_ns,
                expires_at_epoch_ns, issuer_session_identity_digest,
                issuer_measurement_digest,
                issuer_attestation_receipt_digest,
                issuer_credential_issuance_digest, status,
                expected_result_digest, planner_transaction_id,
                authorization_projection_digest,
                selected_business_rows_digest, mutation_plan_digest,
                deadline_epoch_ns
            )
            VALUES (
                capability_value->>'capabilityId',
                computed_capability_digest,
                capability_value->>'envelopeId',
                capability_value->>'operation',
                capability_value->>'operationId',
                capability_value->>'handlerName',
                capability_value->>'requestDigest',
                capability_value->>'operationManifestDigest',
                capability_value->>'queryManifestDigest',
                capability_value->>'authorityRootSetDigest',
                capability_value->>'authoritySnapshotDigest',
                capability_value->>'approverPolicyDigest',
                CASE WHEN capability_value->'webauthnReceipt' =
                    'null'::pg_catalog.jsonb THEN NULL
                    ELSE {namespace}.
                        serverware_policy_authority_wire_json(
                            capability_value->'webauthnReceipt'
                        ) END,
                capability_value->>'webauthnReceiptDigest',
                capability_value->>'webauthnTrustHighWaterDigest',
                computed_reservation_digest,
                (capability_value->>'witnessSequence')::bigint,
                capability_value->>'witnessHeadDigest',
                (capability_value->>'deadlineMonotonicNs')::bigint,
                (capability_value->>'fence')::bigint,
                (capability_value->>'issuedMonotonicNs')::bigint,
                (capability_value->>'issuedAtEpochNs')::bigint,
                (capability_value->>'expiresAtEpochNs')::bigint,
                capability_value->>'issuerSessionIdentityDigest',
                supplied_issuer_measurement_digest,
                supplied_issuer_attestation_receipt_digest,
                supplied_issuer_credential_issuance_digest,
                'issued',
                capability_value->>'expectedResultDigest',
                capability_value->>'plannerTransactionId',
                capability_value->>'authorizationProjectionDigest',
                capability_value->>'selectedBusinessRowsDigest',
                capability_value->>'mutationPlanDigest',
                (capability_value->>'deadlineEpochNs')::bigint
            );
            GET DIAGNOSTICS inserted_count = ROW_COUNT;
            IF inserted_count <> 1 THEN
                RAISE EXCEPTION
                    'writer capability v3 was not inserted';
            END IF;
            INSERT INTO {namespace}.policy_authority_fence_heads (
                authority_scope, fence, witness_sequence,
                witness_head_digest, updated_at_epoch_ns
            )
            VALUES (
                'controlled-writer',
                (capability_value->>'fence')::bigint,
                (capability_value->>'witnessSequence')::bigint,
                capability_value->>'witnessHeadDigest',
                (capability_value->>'issuedAtEpochNs')::bigint
            )
            ON CONFLICT (authority_scope) DO UPDATE
            SET fence = EXCLUDED.fence,
                witness_sequence = EXCLUDED.witness_sequence,
                witness_head_digest = EXCLUDED.witness_head_digest,
                updated_at_epoch_ns = EXCLUDED.updated_at_epoch_ns
            WHERE policy_authority_fence_heads.fence <
                    EXCLUDED.fence
              AND policy_authority_fence_heads.witness_sequence <
                    EXCLUDED.witness_sequence;
            GET DIAGNOSTICS inserted_count = ROW_COUNT;
            IF inserted_count <> 1 THEN
                RAISE EXCEPTION
                    'writer capability v3 fence CAS failed';
            END IF;
            RETURN capability_value->>'capabilityId';
        END;
        $serverware_issue_writer_capability_v3$;

        CREATE OR REPLACE FUNCTION {namespace}.
            serverware_policy_authority_record_witness_receipt(
                witness_receipt_json text,
                supplied_witness_receipt_digest text,
                supplied_issuer_measurement_digest text,
                supplied_issuer_attestation_receipt_digest text
            )
        RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        VOLATILE
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $serverware_record_witness_receipt_v2$
        DECLARE
            receipt_value pg_catalog.jsonb;
            canonical_receipt text;
            computed_receipt_digest text;
            capability record;
            reservation record;
            existing_receipt record;
            inserted_count bigint;
        BEGIN
            IF session_user <> '{capability_issuer_role}'
                OR supplied_issuer_measurement_digest !~
                    '^sha256:[0-9a-f]{{64}}$'
                OR supplied_issuer_attestation_receipt_digest !~
                    '^sha256:[0-9a-f]{{64}}$'
            THEN
                RAISE EXCEPTION
                    'witness v2 recorder identity is not exact';
            END IF;
            receipt_value := witness_receipt_json::pg_catalog.jsonb;
            canonical_receipt := {namespace}.
                serverware_policy_authority_wire_json(receipt_value);
            computed_receipt_digest := {namespace}.
                serverware_policy_authority_domain_digest(
                    'serverware.policyAuthorityReplayWitnessReceipt/v2',
                    canonical_receipt
                );
            IF canonical_receipt IS DISTINCT FROM witness_receipt_json
                OR supplied_witness_receipt_digest IS DISTINCT FROM
                    computed_receipt_digest
                OR pg_catalog.jsonb_typeof(receipt_value) <> 'object'
                OR (
                    SELECT pg_catalog.count(*)
                    FROM pg_catalog.jsonb_object_keys(receipt_value)
                ) <> 21
                OR NOT receipt_value ?& ARRAY[
                    'schema', 'envelopeId', 'parentEnvelopeId',
                    'phase', 'operation', 'requestDigest',
                    'capabilityId', 'resultDigest',
                    'witnessIdentityDigest', 'sequence', 'fence',
                    'headDigest', 'predecessorHeadDigest',
                    'predecessorReceiptDigest',
                    'logPredecessorHeadDigest',
                    'deadlineMonotonicNs', 'issuedAtEpochNs',
                    'generationSequence', 'generationDigest',
                    'canonicalRequestDigest', 'signature'
                ]
                OR receipt_value->>'schema' <>
                    'serverware.policyAuthorityReplayWitnessReceipt/v2'
                OR receipt_value->>'phase' NOT IN (
                    'commit', 'reconcile', 'abort'
                )
                OR receipt_value->>'envelopeId' !~
                    '^sha256:[0-9a-f]{{64}}$'
                OR receipt_value->>'parentEnvelopeId' IS DISTINCT FROM
                    receipt_value->>'predecessorReceiptDigest'
                OR receipt_value->>'headDigest' !~
                    '^sha256:[0-9a-f]{{64}}$'
                OR receipt_value->>'canonicalRequestDigest' !~
                    '^sha256:[0-9a-f]{{64}}$'
                OR (receipt_value->>'sequence')::bigint < 1
                OR (receipt_value->>'fence')::bigint < 1
            THEN
                RAISE EXCEPTION
                    'terminal witness v2 receipt is not closed';
            END IF;
            SELECT * INTO existing_receipt
            FROM {namespace}.policy_authority_external_witness_receipts
            WHERE witness_receipt_digest = computed_receipt_digest;
            IF FOUND THEN
                IF existing_receipt.receipt_json IS DISTINCT FROM
                    canonical_receipt
                THEN
                    RAISE EXCEPTION
                        'terminal witness v2 digest was reused';
                END IF;
                RETURN computed_receipt_digest;
            END IF;
            SELECT * INTO capability
            FROM {namespace}.policy_authority_writer_capabilities
            WHERE capability_id = receipt_value->>'capabilityId'
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    'terminal witness v2 capability is absent';
            END IF;
            SELECT * INTO reservation
            FROM {namespace}.policy_authority_external_witness_receipts
            WHERE witness_receipt_digest =
                capability.witness_reservation_digest
              AND phase IN ('reserve', 'webauthn-trust-publish')
            FOR SHARE;
            IF NOT FOUND
                OR receipt_value->>'operation' <> capability.operation
                OR receipt_value->>'requestDigest' <>
                    capability.request_digest
                OR receipt_value->>'predecessorReceiptDigest' <>
                    capability.witness_reservation_digest
                OR receipt_value->>'predecessorHeadDigest' <>
                    reservation.witness_head_digest
                OR (receipt_value->>'fence')::bigint <>
                    capability.fence
                OR (receipt_value->>'deadlineMonotonicNs')::bigint <>
                    capability.deadline_monotonic_ns
                OR (receipt_value->>'sequence')::bigint <=
                    reservation.witness_sequence
                OR (
                    receipt_value->>'phase' IN ('commit', 'reconcile')
                    AND receipt_value->>'resultDigest' IS DISTINCT FROM
                        capability.result_digest
                )
                OR (
                    receipt_value->>'phase' = 'abort'
                    AND receipt_value->'resultDigest' <>
                        'null'::pg_catalog.jsonb
                )
                OR EXISTS (
                    SELECT 1
                    FROM {namespace}.
                        policy_authority_external_witness_receipts
                    WHERE capability_id = capability.capability_id
                      AND phase IN ('commit', 'reconcile', 'abort')
                )
            THEN
                RAISE EXCEPTION
                    'terminal witness v2 receipt binding is invalid';
            END IF;
            INSERT INTO {namespace}.
                policy_authority_external_witness_receipts (
                    witness_receipt_digest, witness_identity_digest,
                    witness_sequence, witness_head_digest,
                    predecessor_head_digest,
                    predecessor_receipt_digest,
                    log_predecessor_head_digest, phase, operation,
                    request_digest, capability_id, result_digest,
                    fence, receipt_json, recorded_at_epoch_ns
                )
            VALUES (
                computed_receipt_digest,
                receipt_value->>'witnessIdentityDigest',
                (receipt_value->>'sequence')::bigint,
                receipt_value->>'headDigest',
                receipt_value->>'predecessorHeadDigest',
                receipt_value->>'predecessorReceiptDigest',
                receipt_value->>'logPredecessorHeadDigest',
                receipt_value->>'phase', capability.operation,
                capability.request_digest, capability.capability_id,
                CASE WHEN receipt_value->>'phase' = 'abort'
                    THEN NULL ELSE capability.result_digest END,
                capability.fence, canonical_receipt,
                (receipt_value->>'issuedAtEpochNs')::bigint
            );
            GET DIAGNOSTICS inserted_count = ROW_COUNT;
            IF inserted_count <> 1 THEN
                RAISE EXCEPTION
                    'terminal witness v2 receipt was not persisted';
            END IF;
            RETURN computed_receipt_digest;
        END;
        $serverware_record_witness_receipt_v2$;

        CREATE OR REPLACE FUNCTION {namespace}.
            serverware_policy_authority_execute_v9(
                supplied_capability_id text,
                supplied_envelope_id text,
                supplied_planner_transaction_id text,
                supplied_exact_request_base64url text,
                supplied_exact_result_base64url text
            )
        RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        VOLATILE
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $serverware_execute_v9$
        DECLARE
            fence_head record;
            capability record;
            execution_envelope record;
            planner record;
            authorization_projection record;
            assertion_evidence record;
            trust_high_water record;
            trust_publication record;
            manifest_row record;
            root_row record;
            selected_row pg_catalog.jsonb;
            mutation pg_catalog.jsonb;
            authorization_source pg_catalog.jsonb;
            key_columns pg_catalog.jsonb;
            key_names text[];
            supplied_key_names text[];
            key_predicate text;
            update_columns text;
            current_row pg_catalog.jsonb;
            post_row pg_catalog.jsonb;
            request_bytes bytea;
            result_bytes bytea;
            canonical_result text;
            computed_result_digest text;
            computed_authority_snapshot_digest text;
            trust_high_water_value pg_catalog.jsonb;
            computed_trust_high_water_digest text;
            root_set_before_json text;
            root_set_before_digest text;
            authorization_root_set_json text;
            authorization_root_set_digest text;
            root_set_after_json text;
            root_set_after_digest text;
            receipt_value pg_catalog.jsonb;
            receipt_json text;
            receipt_digest text;
            expected_operation text;
            now_epoch_ns numeric;
            matched_count bigint;
            mutation_count bigint;
            selected_count bigint;
            {root_transition_declarations_sql()}
            operation_handlers constant pg_catalog.jsonb :=
                '{operation_handlers}'::pg_catalog.jsonb;
            assertion_requirements constant pg_catalog.jsonb :=
                '{assertion_requirements}'::pg_catalog.jsonb;
            operation_manifest_counts constant pg_catalog.jsonb :=
                '{operation_manifest_counts}'::pg_catalog.jsonb;
            operation_limits constant pg_catalog.jsonb :=
                '{operation_limits}'::pg_catalog.jsonb;
            authorization_manifest_counts constant pg_catalog.jsonb :=
                '{authorization_manifest_counts}'::pg_catalog.jsonb;
            authorization_read_sets constant pg_catalog.jsonb :=
                '{authorization_read_sets}'::pg_catalog.jsonb;
        BEGIN
            IF pg_catalog.current_setting('transaction_isolation') <>
                    'serializable'
            THEN
                RAISE EXCEPTION
                    'authority v9 executor requires SERIALIZABLE';
            END IF;
            expected_operation := pg_catalog.current_setting(
                'serverware.policy_authority_expected_operation',
                true
            );
            IF expected_operation IS NULL OR expected_operation = '' THEN
                RAISE EXCEPTION
                    'authority v9 central executor is owner-private';
            END IF;
            PERFORM pg_catalog.set_config(
                'lock_timeout', '500ms', true
            );
            PERFORM pg_catalog.set_config(
                'statement_timeout', '5s', true
            );
            IF supplied_exact_request_base64url !~
                    '^[A-Za-z0-9_-]+$'
                OR supplied_exact_result_base64url !~
                    '^[A-Za-z0-9_-]+$'
            THEN
                RAISE EXCEPTION
                    'authority v9 exact bytes are not canonical base64url';
            END IF;

            SELECT *
            INTO STRICT fence_head
            FROM {namespace}.policy_authority_fence_heads
            WHERE authority_scope = 'controlled-writer'
            FOR UPDATE;

            SELECT *
            INTO STRICT capability
            FROM {namespace}.policy_authority_writer_capabilities
            WHERE capability_id = supplied_capability_id
            FOR UPDATE;
            IF capability.operation <> expected_operation THEN
                RAISE EXCEPTION
                    'authority v9 operation wrapper binding changed';
            END IF;

            SELECT *
            INTO STRICT execution_envelope
            FROM {namespace}.policy_authority_execution_envelopes
            WHERE envelope_id = supplied_envelope_id
            FOR UPDATE;
            SELECT *
            INTO STRICT planner
            FROM {namespace}.policy_authority_planner_transactions
            WHERE planner_transaction_id =
                supplied_planner_transaction_id
            FOR UPDATE;
            {load_root_transition_sql(namespace)}
            IF capability.status = 'committed' THEN
                IF execution_envelope.status <> 'committed'
                    OR planner.status <> 'consumed'
                    OR execution_envelope.capability_id <>
                        capability.capability_id
                    OR planner.capability_id <> capability.capability_id
                    OR execution_envelope.planner_transaction_id <>
                        planner.planner_transaction_id
                    OR execution_envelope.exact_request_base64url <>
                        supplied_exact_request_base64url
                    OR execution_envelope.exact_response_base64url <>
                        supplied_exact_result_base64url
                    OR planner.exact_response_base64url <>
                        supplied_exact_result_base64url
                    OR execution_envelope.terminal_receipt_json IS NULL
                    OR execution_envelope.terminal_receipt_json <>
                        planner.terminal_receipt_json
                    OR execution_envelope.terminal_receipt_digest <>
                        planner.terminal_receipt_digest
                    OR execution_envelope.terminal_receipt_json <>
                        {namespace}.
                            serverware_policy_authority_wire_json(
                                execution_envelope.terminal_receipt_json
                                    ::pg_catalog.jsonb
                            )
                    OR execution_envelope.terminal_receipt_digest <>
                        {namespace}.
                            serverware_policy_authority_domain_digest(
                                'serverware.policyAuthorityWriterCommitReceipt/v2',
                                execution_envelope.terminal_receipt_json
                            )
                    OR capability.commit_receipt_digest <>
                        execution_envelope.terminal_receipt_digest
                THEN
                    RAISE EXCEPTION
                        'authority v9 committed retry is not exact';
                END IF;
                {assert_root_transition_replay_sql(namespace)}
                RETURN execution_envelope.terminal_receipt_json;
            ELSIF capability.status <> 'issued'
                OR execution_envelope.status <> 'reserved'
                OR planner.status <> 'planned'
            THEN
                RAISE EXCEPTION
                    'authority v9 one-use state is terminal or inconsistent';
            END IF;
            SELECT *
            INTO STRICT authorization_projection
            FROM {namespace}.policy_authority_authorization_projections
            WHERE authorization_projection_digest =
                planner.authorization_projection_digest
            FOR UPDATE;
            IF authorization_projection.assertion_evidence_digest
                    IS NOT NULL
            THEN
                SELECT *
                INTO STRICT assertion_evidence
                FROM {namespace}.
                    policy_authority_webauthn_assertion_evidence
                WHERE assertion_evidence_digest =
                    authorization_projection.assertion_evidence_digest
                FOR UPDATE;
                {locked_webauthn_trust_projection(namespace)}
                trust_high_water_value :=
                    pg_catalog.jsonb_build_object(
                        'schema',
                            'serverware.webauthnTrustHighWater/v1',
                        'rollbackEpoch',
                            trust_publication.rollback_epoch,
                        'sequence', trust_publication.sequence,
                        'publicationDigest',
                            trust_publication.publication_digest,
                        'metadataBlobDigest',
                            trust_publication.metadata_blob_digest,
                        'revocationSetDigest',
                            trust_publication.revocation_set_digest,
                        'witnessReceiptDigest',
                            trust_publication.witness_receipt_digest,
                        'witnessSequence',
                            trust_publication.witness_sequence
                    );
                computed_trust_high_water_digest :=
                    {namespace}.
                        serverware_policy_authority_domain_digest(
                            'serverware.webauthnTrustHighWater/v1',
                            {namespace}.
                                serverware_policy_authority_wire_json(
                                    trust_high_water_value
                                )
                        );
            END IF;
            FOR manifest_row IN
                SELECT *
                FROM {namespace}.
                    policy_authority_query_dependency_manifests
                WHERE operation = capability.operation
                ORDER BY ordinal
                FOR UPDATE
            LOOP
                NULL;
            END LOOP;
            FOR manifest_row IN
                SELECT *
                FROM {namespace}.
                    policy_authority_authorization_dependency_manifests
                WHERE operation = capability.operation
                ORDER BY table_name COLLATE "C"
                FOR UPDATE
            LOOP
                NULL;
            END LOOP;
            IF (
                    SELECT pg_catalog.count(*)
                    FROM {namespace}.
                        policy_authority_authorization_dependency_manifests
                    WHERE operation = capability.operation
                ) <> (
                    authorization_manifest_counts->>capability.operation
                )::bigint
                OR (
                    SELECT pg_catalog.count(*)
                    FROM {namespace}.
                        policy_authority_authenticated_table_roots
                        AS roots
                    WHERE roots.table_name IN (
                        SELECT dependency.table_name
                        FROM {namespace}.
                            policy_authority_authorization_dependency_manifests
                            AS dependency
                        WHERE dependency.operation = capability.operation
                    )
                ) <> (
                    authorization_manifest_counts->>capability.operation
                )::bigint
            THEN
                RAISE EXCEPTION
                    'authority authorization manifest is incomplete';
            END IF;
            FOR root_row IN
                SELECT roots.*
                FROM {namespace}.
                    policy_authority_authenticated_table_roots AS roots
                WHERE roots.table_name IN (
                    SELECT dependency.table_name
                    FROM {namespace}.
                        policy_authority_authorization_dependency_manifests
                        AS dependency
                    WHERE dependency.operation = capability.operation
                )
                ORDER BY roots.table_name COLLATE "C"
                FOR UPDATE
            LOOP
                NULL;
            END LOOP;
            SELECT {namespace}.serverware_policy_authority_wire_json(
                pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'table', roots.table_name,
                        'rootRevision', roots.root_revision,
                        'rootDigest', roots.root_digest,
                        'leafCount', roots.leaf_count
                    )
                    ORDER BY roots.table_name COLLATE "C"
                )
            )
            INTO authorization_root_set_json
            FROM {namespace}.policy_authority_authenticated_table_roots
                AS roots
            WHERE roots.table_name IN (
                SELECT dependency.table_name
                FROM {namespace}.
                    policy_authority_authorization_dependency_manifests
                    AS dependency
                WHERE dependency.operation = capability.operation
            );
            authorization_root_set_digest :=
                {namespace}.serverware_policy_authority_domain_digest(
                    'serverware.policyAuthorityAuthorizationRootSet/v1',
                    COALESCE(authorization_root_set_json, '[]')
                );
            IF pg_catalog.jsonb_typeof(
                    authorization_projection.source_rows_json
                        ::pg_catalog.jsonb
                ) <> 'array'
                OR pg_catalog.jsonb_array_length(
                    authorization_projection.source_rows_json
                        ::pg_catalog.jsonb
                ) > 64
                OR EXISTS (
                    SELECT 1
                    FROM {namespace}.
                        policy_authority_authorization_dependency_manifests
                        AS dependency
                    WHERE dependency.operation = capability.operation
                      AND NOT EXISTS (
                            SELECT 1
                            FROM pg_catalog.jsonb_array_elements(
                                authorization_projection.source_rows_json
                                    ::pg_catalog.jsonb
                            ) AS projected(value)
                            WHERE projected.value->>'table' =
                                    dependency.table_name
                        )
                )
            THEN
                RAISE EXCEPTION
                    'authority authorization projection is not closed';
            END IF;
            FOR authorization_source IN
                SELECT projected.value
                FROM pg_catalog.jsonb_array_elements(
                    authorization_projection.source_rows_json
                        ::pg_catalog.jsonb
                ) AS projected(value)
                ORDER BY projected.value->>'table' COLLATE "C",
                    {namespace}.
                        serverware_policy_authority_wire_json(
                            projected.value->'selector'
                        ) COLLATE "C"
            LOOP
                IF NOT {closed_record_sql('authorization_source')}
                    OR pg_catalog.jsonb_typeof(
                        authorization_source->'selector'
                    ) IS DISTINCT FROM 'object'
                    OR NOT EXISTS (
                        SELECT 1
                        FROM {namespace}.
                            policy_authority_authorization_dependency_manifests
                            AS dependency
                        WHERE dependency.operation = capability.operation
                          AND dependency.table_name =
                                authorization_source->>'table'
                    )
                THEN
                    RAISE EXCEPTION
                        'authority authorization source is outside manifest';
                END IF;
                SELECT dependency.key_columns_json::pg_catalog.jsonb
                INTO STRICT key_columns
                FROM {namespace}.
                    policy_authority_authorization_dependency_manifests
                    AS dependency
                WHERE dependency.operation = capability.operation
                  AND dependency.table_name =
                        authorization_source->>'table';
                SELECT pg_catalog.array_agg(
                    value ORDER BY value COLLATE "C"
                )
                INTO key_names
                FROM pg_catalog.jsonb_array_elements_text(key_columns);
                SELECT pg_catalog.array_agg(
                    key ORDER BY key COLLATE "C"
                )
                INTO supplied_key_names
                FROM pg_catalog.jsonb_object_keys(
                    authorization_source->'selector'
                ) AS key;
                IF key_names IS DISTINCT FROM supplied_key_names THEN
                    RAISE EXCEPTION
                        'authority authorization selector is not exact';
                END IF;
                {locked_primary_key_row_sql(namespace, 'authorization_source')}
                IF NOT {selected_row_matches_sql('authorization_source')}
                    OR authorization_source->>'rowDigest'
                        IS DISTINCT FROM
                        {namespace}.
                            serverware_policy_authority_domain_digest(
                                'serverware.policyAuthorityAuthorizationRow/v1',
                                authorization_source->>'table',
                                {namespace}.
                                    serverware_policy_authority_wire_json(
                                        authorization_source->'selector'
                                    ),
                                CASE
                                    WHEN current_row IS NULL
                                    THEN 'absent'
                                    ELSE 'present'
                                END,
                                CASE
                                    WHEN current_row IS NULL
                                    THEN 'null'
                                    ELSE {namespace}.
                                        serverware_policy_authority_wire_json(
                                            current_row
                                        )
                                END
                            )
                THEN
                    RAISE EXCEPTION
                        'authority authorization source changed';
                END IF;
            END LOOP;

            FOR root_row IN
                SELECT roots.*
                FROM {namespace}.
                    policy_authority_authenticated_table_roots AS roots
                WHERE roots.table_name IN (
                    SELECT dependency.table_name
                    FROM {namespace}.
                        policy_authority_query_dependency_manifests
                        AS dependency
                    WHERE dependency.operation = capability.operation
                )
                ORDER BY roots.table_name COLLATE "C"
                FOR UPDATE
            LOOP
                NULL;
            END LOOP;
            SELECT {namespace}.serverware_policy_authority_wire_json(
                pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'table', roots.table_name,
                        'rootRevision', roots.root_revision,
                        'rootDigest', roots.root_digest,
                        'leafCount', roots.leaf_count
                    )
                    ORDER BY roots.table_name COLLATE "C"
                )
            )
            INTO root_set_before_json
            FROM {namespace}.policy_authority_authenticated_table_roots
                AS roots
            WHERE roots.table_name IN (
                SELECT dependency.table_name
                FROM {namespace}.
                    policy_authority_query_dependency_manifests
                    AS dependency
                WHERE dependency.operation = capability.operation
            );
            root_set_before_digest :=
                {namespace}.serverware_policy_authority_domain_digest(
                    'serverware.policyAuthorityRootSet/v1',
                    COALESCE(root_set_before_json, '[]')
                );
            {assert_root_transition_before_sql(namespace)}

            IF pg_catalog.jsonb_typeof(
                    planner.selected_business_rows_json::pg_catalog.jsonb
                ) <> 'array'
                OR pg_catalog.jsonb_typeof(
                    planner.mutation_plan_json::pg_catalog.jsonb
                ) <> 'array'
            THEN
                RAISE EXCEPTION
                    'authority v9 planner sets are not arrays';
            END IF;
            selected_count := pg_catalog.jsonb_array_length(
                planner.selected_business_rows_json::pg_catalog.jsonb
            );
            mutation_count := pg_catalog.jsonb_array_length(
                planner.mutation_plan_json::pg_catalog.jsonb
            );
            IF selected_count > (
                    operation_limits -> (capability.operation)
                        ->> 'maximumQueryRows'
                )::bigint
                OR mutation_count > (
                    operation_limits -> (capability.operation)
                        ->> 'maximumMutations'
                )::bigint
                OR planner.work_units > (
                    operation_limits -> (capability.operation)
                        ->> 'maximumWorkUnits'
                )::bigint
            THEN
                RAISE EXCEPTION
                    'authority v9 planner bound is exceeded';
            END IF;
            IF selected_count <> (
                    SELECT pg_catalog.count(*)
                    FROM (
                        SELECT selected.value->>'table',
                            selected.value->'key'
                        FROM pg_catalog.jsonb_array_elements(
                            planner.selected_business_rows_json
                                ::pg_catalog.jsonb
                        ) AS selected(value)
                        GROUP BY selected.value->>'table',
                            selected.value->'key'
                    ) AS distinct_selected
                )
                OR mutation_count <> (
                    SELECT pg_catalog.count(*)
                    FROM (
                        SELECT planned.value->>'table',
                            planned.value->'key'
                        FROM pg_catalog.jsonb_array_elements(
                            planner.mutation_plan_json
                                ::pg_catalog.jsonb
                        ) AS planned(value)
                        GROUP BY planned.value->>'table',
                            planned.value->'key'
                    ) AS distinct_mutations
                )
            THEN
                RAISE EXCEPTION
                    'authority v9 planner contains a canonical key collision';
            END IF;

            FOR selected_row IN
                SELECT selected.value
                FROM pg_catalog.jsonb_array_elements(
                    planner.selected_business_rows_json
                        ::pg_catalog.jsonb
                ) AS selected(value)
                ORDER BY selected.value->>'table' COLLATE "C",
                    selected.value->>'keyDigest' COLLATE "C"
            LOOP
                IF pg_catalog.jsonb_typeof(selected_row) <> 'object'
                    OR pg_catalog.jsonb_typeof(
                        selected_row->'key'
                    ) <> 'object'
                    OR (
                        NOT EXISTS (
                            SELECT 1
                            FROM {namespace}.
                                policy_authority_query_dependency_manifests
                                AS dependency
                            WHERE dependency.operation = capability.operation
                              AND dependency.table_name =
                                    selected_row->>'table'
                        )
                        AND NOT EXISTS (
                            SELECT 1
                            FROM {namespace}.
                                policy_authority_authorization_dependency_manifests
                                AS dependency
                            WHERE dependency.operation = capability.operation
                              AND dependency.table_name =
                                    selected_row->>'table'
                        )
                    )
                    OR selected_row->>'keyDigest' IS DISTINCT FROM
                        {namespace}.
                            serverware_policy_authority_domain_digest(
                                'serverware.policyAuthorityBusinessKey/v1',
                                selected_row->>'table',
                                {namespace}.
                                    serverware_policy_authority_wire_json(
                                        selected_row->'key'
                                    )
                            )
                THEN
                    RAISE EXCEPTION
                        'authority v9 selected row is outside the manifest';
                END IF;
                SELECT dependency.key_columns_json::pg_catalog.jsonb
                INTO STRICT key_columns
                FROM (
                    SELECT business.operation, business.table_name,
                        business.key_columns_json
                    FROM {namespace}.
                        policy_authority_query_dependency_manifests
                        AS business
                    UNION ALL
                    SELECT authorization.operation,
                        authorization.table_name,
                        authorization.key_columns_json
                    FROM {namespace}.
                        policy_authority_authorization_dependency_manifests
                        AS authorization
                ) AS dependency
                WHERE dependency.operation = capability.operation
                  AND dependency.table_name = selected_row->>'table';
                SELECT pg_catalog.array_agg(value ORDER BY value COLLATE "C")
                INTO key_names
                FROM pg_catalog.jsonb_array_elements_text(key_columns);
                SELECT pg_catalog.array_agg(key ORDER BY key COLLATE "C")
                INTO supplied_key_names
                FROM pg_catalog.jsonb_object_keys(
                    selected_row->'key'
                ) AS key;
                IF key_names IS DISTINCT FROM supplied_key_names THEN
                    RAISE EXCEPTION
                        'authority v9 selected key is not exact';
                END IF;
                {locked_primary_key_row_sql(namespace, 'selected_row')}
                IF NOT {selected_row_matches_sql('selected_row')} THEN
                    RAISE EXCEPTION
                        'authority v9 selected business row changed';
                END IF;
            END LOOP;

            request_bytes := pg_catalog.decode(
                pg_catalog.translate(
                    supplied_exact_request_base64url, '-_', '+/'
                )
                || pg_catalog.repeat(
                    '=',
                    (4 - pg_catalog.length(
                        supplied_exact_request_base64url
                    ) % 4) % 4
                ),
                'base64'
            );
            result_bytes := pg_catalog.decode(
                pg_catalog.translate(
                    supplied_exact_result_base64url, '-_', '+/'
                )
                || pg_catalog.repeat(
                    '=',
                    (4 - pg_catalog.length(
                        supplied_exact_result_base64url
                    ) % 4) % 4
                ),
                'base64'
            );
            {assert_root_transition_payload_sql(namespace)}
            computed_result_digest :=
                {namespace}.serverware_policy_authority_domain_digest(
                    'serverware.policyAuthorityControlledWriterResult/v2',
                    canonical_result
                );
            computed_authority_snapshot_digest :=
                {namespace}.serverware_policy_authority_domain_digest(
                    'serverware.policyAuthoritySnapshot/v3',
                    capability.operation,
                    capability.operation_id,
                    capability.request_digest,
                    capability.query_manifest_digest,
                    root_set_before_digest,
                    authorization_projection.
                        authorization_projection_digest,
                    planner.selected_business_rows_digest,
                    planner.mutation_plan_digest,
                    rt_transition_digest
                );
            now_epoch_ns := pg_catalog.floor(
                EXTRACT(
                    EPOCH FROM pg_catalog.clock_timestamp()
                ) * 1000000000
            );
            IF fence_head.fence <> capability.fence
                OR capability.status <> 'issued'
                OR capability.envelope_id <> supplied_envelope_id
                OR capability.operation_manifest_digest <>
                    '{operation_manifest_digest}'
                OR capability.operation_manifest_digest <>
                    execution_envelope.operation_contract_digest
                OR capability.planner_transaction_id <>
                    planner.planner_transaction_id
                OR capability.authorization_projection_digest <>
                    authorization_projection.
                        authorization_projection_digest
                OR capability.selected_business_rows_digest <>
                    planner.selected_business_rows_digest
                OR capability.mutation_plan_digest <>
                    planner.mutation_plan_digest
                OR capability.expected_result_digest <>
                    computed_result_digest
                OR capability.authority_snapshot_digest <>
                    computed_authority_snapshot_digest
                OR planner.authority_snapshot_digest <>
                    computed_authority_snapshot_digest
                OR planner.selected_business_rows_json IS DISTINCT FROM
                    {namespace}.
                        serverware_policy_authority_wire_json(
                            planner.selected_business_rows_json
                                ::pg_catalog.jsonb
                        )
                OR planner.mutation_plan_json IS DISTINCT FROM
                    {namespace}.
                        serverware_policy_authority_wire_json(
                            planner.mutation_plan_json::pg_catalog.jsonb
                        )
                OR planner.selected_business_rows_digest IS DISTINCT FROM
                    {namespace}.serverware_policy_authority_domain_digest(
                        'serverware.policyAuthoritySelectedBusinessRows/v1',
                        planner.selected_business_rows_json
                    )
                OR planner.mutation_plan_digest IS DISTINCT FROM
                    {namespace}.serverware_policy_authority_domain_digest(
                        'serverware.policyAuthorityMutationPlan/v3',
                        planner.mutation_plan_json
                    )
                OR capability.operation <> execution_envelope.operation
                OR capability.operation <> planner.operation
                OR capability.operation_id <>
                    execution_envelope.operation_id
                OR capability.operation_id <> planner.operation_id
                OR capability.request_digest <>
                    execution_envelope.request_digest
                OR capability.request_digest <> planner.request_digest
                OR capability.capability_id <>
                    execution_envelope.capability_id
                OR capability.capability_id <> planner.capability_id
                OR execution_envelope.planner_transaction_id <>
                    planner.planner_transaction_id
                OR execution_envelope.authorization_projection_digest <>
                    authorization_projection.
                        authorization_projection_digest
                OR planner.authorization_projection_digest <>
                    authorization_projection.
                        authorization_projection_digest
                OR authorization_projection.operation <>
                    capability.operation
                OR authorization_projection.operation_id <>
                    capability.operation_id
                OR authorization_projection.request_digest <>
                    capability.request_digest
                OR authorization_projection.capability_id <>
                    capability.capability_id
                OR authorization_projection.approver_policy_digest
                    IS DISTINCT FROM capability.approver_policy_digest
                OR capability.query_manifest_digest <>
                    planner.query_manifest_digest
                OR (
                    SELECT pg_catalog.count(*)
                    FROM {namespace}.
                        policy_authority_query_dependency_manifests
                    WHERE operation = capability.operation
                ) <> (
                    operation_manifest_counts->>capability.operation
                )::bigint
                OR EXISTS (
                    SELECT 1
                    FROM {namespace}.
                        policy_authority_query_dependency_manifests
                    WHERE operation = capability.operation
                      AND manifest_digest <>
                            capability.query_manifest_digest
                )
                OR execution_envelope.status <> 'reserved'
                OR planner.status <> 'planned'
                OR capability.deadline_monotonic_ns <>
                    execution_envelope.deadline_monotonic_ns
                OR capability.deadline_monotonic_ns <>
                    planner.deadline_monotonic_ns
                OR capability.deadline_epoch_ns <>
                    execution_envelope.deadline_epoch_ns
                OR capability.deadline_epoch_ns <>
                    planner.deadline_epoch_ns
                OR capability.fence <> execution_envelope.fence
                OR capability.fence <> planner.fence
                OR now_epoch_ns >= execution_envelope.deadline_epoch_ns
                OR now_epoch_ns >= planner.deadline_epoch_ns
                OR now_epoch_ns >= capability.deadline_epoch_ns
                OR now_epoch_ns >= authorization_projection.expires_at_epoch_ns
                OR authorization_projection.projection_json IS DISTINCT FROM
                    {namespace}.
                        serverware_policy_authority_wire_json(
                            authorization_projection.projection_json
                                ::pg_catalog.jsonb
                        )
                OR authorization_projection.
                    authorization_projection_digest IS DISTINCT FROM
                    {namespace}.serverware_policy_authority_domain_digest(
                        'serverware.policyAuthorityAuthorizationProjection/v1',
                        authorization_projection.projection_json
                    )
                OR authorization_projection.authorization_reads_digest
                    IS DISTINCT FROM
                    {namespace}.serverware_policy_authority_domain_digest(
                        'serverware.policyAuthorityAuthorizationReads/v1',
                        authorization_projection.authorization_reads_json
                    )
                OR authorization_projection.authorization_reads_json
                        ::pg_catalog.jsonb IS DISTINCT FROM
                    authorization_read_sets->capability.operation
                OR authorization_projection.source_high_water_digest <>
                    authorization_root_set_digest
                OR authorization_projection.source_rows_digest
                    IS DISTINCT FROM
                    {namespace}.serverware_policy_authority_domain_digest(
                        'serverware.policyAuthorityAuthorizationRows/v1',
                        authorization_projection.source_rows_json
                    )
                OR (
                    (
                        assertion_requirements->>capability.operation
                    )::boolean
                    AND authorization_projection.
                        assertion_evidence_digest IS NULL
                )
                OR (
                    authorization_projection.assertion_evidence_digest
                        IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1
                        FROM {namespace}.
                            policy_authority_webauthn_assertion_evidence
                            AS evidence
                        WHERE evidence.assertion_evidence_digest =
                                authorization_projection.
                                    assertion_evidence_digest
                          AND evidence.operation = capability.operation
                          AND evidence.operation_id =
                                capability.operation_id
                          AND evidence.request_digest =
                                capability.request_digest
                          AND evidence.capability_id =
                                capability.capability_id
                          AND evidence.verified_assertion_receipt_digest =
                                capability.webauthn_receipt_digest
                          AND evidence.trust_high_water_digest =
                                capability.webauthn_trust_high_water_digest
                          AND evidence.trust_high_water_digest =
                                computed_trust_high_water_digest
                          AND evidence.metadata_publication_sequence =
                                trust_publication.sequence
                          AND evidence.challenge_id =
                                capability.webauthn_receipt_json
                                    ::pg_catalog.jsonb->>'challengeId'
                          AND evidence.challenge_digest =
                                capability.webauthn_receipt_json
                                    ::pg_catalog.jsonb->>'challengeDigest'
                          AND evidence.credential_record_id =
                                capability.webauthn_receipt_json
                                    ::pg_catalog.jsonb
                                    ->>'credentialRecordId'
                          AND evidence.credential_id =
                                capability.webauthn_receipt_json
                                    ::pg_catalog.jsonb->>'credentialId'
                          AND evidence.credential_policy_digest =
                                capability.webauthn_receipt_json
                                    ::pg_catalog.jsonb
                                    ->>'credentialPolicyDigest'
                          AND evidence.client_data_json_digest =
                                capability.webauthn_receipt_json
                                    ::pg_catalog.jsonb
                                    ->>'clientDataJSONDigest'
                          AND evidence.authenticator_data_digest =
                                capability.webauthn_receipt_json
                                    ::pg_catalog.jsonb
                                    ->>'authenticatorDataDigest'
                          AND evidence.signature_digest =
                                capability.webauthn_receipt_json
                                    ::pg_catalog.jsonb->>'signatureDigest'
                          AND evidence.flags = (
                                capability.webauthn_receipt_json
                                    ::pg_catalog.jsonb->>'flags'
                              )::bigint
                          AND evidence.prior_counter = (
                                capability.webauthn_receipt_json
                                    ::pg_catalog.jsonb->>'priorCounter'
                              )::bigint
                          AND evidence.counter = (
                                capability.webauthn_receipt_json
                                    ::pg_catalog.jsonb->>'counter'
                              )::bigint
                          AND evidence.evidence_json =
                                {namespace}.
                                    serverware_policy_authority_wire_json(
                                        evidence.evidence_json
                                            ::pg_catalog.jsonb
                                    )
                          AND evidence.assertion_evidence_digest =
                                {namespace}.
                                    serverware_policy_authority_domain_digest(
                                        'serverware.policyAuthorityWebAuthnAssertionEvidence/v1',
                                        evidence.evidence_json
                                    )
                          AND now_epoch_ns <
                                evidence.expires_at_epoch_ns
                    )
                )
                OR operation_handlers->>capability.operation
                    IS DISTINCT FROM capability.handler_name
                OR root_set_before_digest <>
                    planner.authority_root_set_before_digest
                OR root_set_before_digest <>
                    capability.authority_root_set_digest
            THEN
                RAISE EXCEPTION
                    'authority v9 closed preconditions changed';
            END IF;

            IF (
                assertion_requirements->>capability.operation
            )::boolean
            THEN
                IF NOT EXISTS (
                        SELECT 1
                        FROM pg_catalog.jsonb_array_elements(
                            planner.mutation_plan_json::pg_catalog.jsonb
                        ) AS challenge_mutation(value)
                        WHERE challenge_mutation.value->>'table' =
                                'webauthn_challenges'
                          AND challenge_mutation.value->'key'->>'id' =
                                assertion_evidence.challenge_id
                          AND challenge_mutation.value->>'operation' =
                                'UPDATE'
                          AND challenge_mutation.value->'expectedRow'
                                ->>'used_at' IS NULL
                          AND {namespace}.
                                serverware_policy_authority_domain_digest(
                                    'serverware.policyAuthorityWebAuthnChallengeRow/v1',
                                    {namespace}.
                                        serverware_policy_authority_wire_json(
                                            challenge_mutation.value
                                                ->'expectedRow'
                                        )
                                ) =
                                capability.webauthn_receipt_json
                                    ::pg_catalog.jsonb
                                    ->>'challengeRowDigest'
                          AND challenge_mutation.value->'row'
                                ->>'used_at' IS NOT NULL
                    )
                    OR NOT EXISTS (
                        SELECT 1
                        FROM pg_catalog.jsonb_array_elements(
                            planner.mutation_plan_json::pg_catalog.jsonb
                        ) AS credential_mutation(value)
                        WHERE credential_mutation.value->>'table' =
                                'webauthn_credentials'
                          AND credential_mutation.value->'key'->>'id' =
                                assertion_evidence.credential_record_id
                          AND credential_mutation.value->>'operation' =
                                'UPDATE'
                          AND credential_mutation.value->'expectedRow'
                                ->>'credential_id' =
                                assertion_evidence.credential_id
                          AND (
                                credential_mutation.value->'expectedRow'
                                    ->>'sign_count'
                              )::bigint =
                                assertion_evidence.prior_counter
                          AND credential_mutation.value->'expectedRow'
                                ->>'revoked_at' IS NULL
                          AND credential_mutation.value->'expectedRow'
                                ->>'attestation_trust_bundle_digest' =
                                trust_publication.bundle_digest
                          AND (
                                credential_mutation.value->'expectedRow'
                                    ->>'attestation_trust_bundle_sequence'
                              )::bigint = trust_publication.sequence
                          AND {namespace}.
                                serverware_policy_authority_domain_digest(
                                    'serverware.policyAuthorityWebAuthnCredentialBinding/v1',
                                    {namespace}.
                                        serverware_policy_authority_wire_json(
                                            pg_catalog.jsonb_build_object(
                                                'id',
                                                    credential_mutation.value
                                                        ->'expectedRow'->>'id',
                                                'credential_id',
                                                    credential_mutation.value
                                                        ->'expectedRow'
                                                        ->>'credential_id',
                                                'user_id',
                                                    credential_mutation.value
                                                        ->'expectedRow'
                                                        ->>'user_id',
                                                'public_key_cose',
                                                    credential_mutation.value
                                                        ->'expectedRow'
                                                        ->>'public_key_cose',
                                                'sign_count',
                                                    (
                                                        credential_mutation.
                                                            value
                                                            ->'expectedRow'
                                                            ->>'sign_count'
                                                    )::bigint,
                                                'aaguid',
                                                    credential_mutation.value
                                                        ->'expectedRow'
                                                        ->'aaguid',
                                                'authenticator_class',
                                                    credential_mutation.value
                                                        ->'expectedRow'
                                                        ->>'authenticator_class',
                                                'attestation_trusted',
                                                    (
                                                        credential_mutation.
                                                            value
                                                            ->'expectedRow'
                                                            ->>'attestation_trusted'
                                                    )::bigint,
                                                'attestation_leaf_sha256',
                                                    credential_mutation.value
                                                        ->'expectedRow'
                                                        ->'attestation_leaf_sha256',
                                                'attestation_root_sha256',
                                                    credential_mutation.value
                                                        ->'expectedRow'
                                                        ->'attestation_root_sha256',
                                                'attestation_trust_bundle_digest',
                                                    credential_mutation.value
                                                        ->'expectedRow'
                                                        ->'attestation_trust_bundle_digest',
                                                'attestation_trust_bundle_sequence',
                                                    (
                                                        credential_mutation.
                                                            value
                                                            ->'expectedRow'
                                                            ->>'attestation_trust_bundle_sequence'
                                                    )::bigint,
                                                'revoked_at',
                                                    credential_mutation.value
                                                        ->'expectedRow'
                                                        ->'revoked_at'
                                            )
                                        )
                                ) =
                                capability.webauthn_receipt_json
                                    ::pg_catalog.jsonb
                                    ->>'credentialBindingDigest'
                          AND {namespace}.
                                serverware_policy_authority_domain_digest(
                                    'serverware.policyAuthorityCredentialPolicy/v1',
                                    {namespace}.
                                        serverware_policy_authority_wire_json(
                                            pg_catalog.jsonb_build_object(
                                                'schema',
                                                    'serverware.policyAuthorityCredentialPolicy/v1',
                                                'credentialRecordId',
                                                    assertion_evidence.
                                                        credential_record_id,
                                                'credentialId',
                                                    assertion_evidence.
                                                        credential_id,
                                                'userId',
                                                    credential_mutation.value
                                                        ->'expectedRow'
                                                        ->>'user_id',
                                                'authenticatorClass',
                                                    credential_mutation.value
                                                        ->'expectedRow'
                                                        ->>'authenticator_class',
                                                'attestationTrusted',
                                                    (
                                                        credential_mutation.
                                                            value
                                                            ->'expectedRow'
                                                            ->>'attestation_trusted'
                                                    )::bigint = 1,
                                                'attestationLeafDigest',
                                                    credential_mutation.value
                                                        ->'expectedRow'
                                                        ->'attestation_leaf_sha256',
                                                'attestationRootDigest',
                                                    credential_mutation.value
                                                        ->'expectedRow'
                                                        ->'attestation_root_sha256',
                                                'trustBundleDigest',
                                                    trust_publication.
                                                        bundle_digest,
                                                'trustBundleSequence',
                                                    trust_publication.sequence,
                                                'trustRollbackEpoch',
                                                    trust_publication.
                                                        rollback_epoch,
                                                'trustHighWaterDigest',
                                                    computed_trust_high_water_digest,
                                                'revocationSetDigest',
                                                    trust_publication.
                                                        revocation_set_digest,
                                                'trustWitnessReceiptDigest',
                                                    trust_publication.
                                                        witness_receipt_digest,
                                                'publicKeyDigest',
                                                    'sha256:' ||
                                                    pg_catalog.encode(
                                                        pg_catalog.sha256(
                                                            pg_catalog.convert_to(
                                                                credential_mutation.
                                                                    value
                                                                    ->'expectedRow'
                                                                    ->>'public_key_cose',
                                                                'UTF8'
                                                            )
                                                        ),
                                                        'hex'
                                                    )
                                            )
                                        )
                                ) = assertion_evidence.
                                        credential_policy_digest
                          AND NOT (
                                assertion_evidence.credential_id = ANY (
                                    SELECT
                                        pg_catalog.jsonb_array_elements_text(
                                            trust_publication.
                                                withdrawn_credential_ids_json
                                                ::pg_catalog.jsonb
                                        )
                                )
                                OR
                                assertion_evidence.credential_record_id =
                                    ANY (
                                        SELECT
                                            pg_catalog.
                                                jsonb_array_elements_text(
                                                    trust_publication.
                                                        withdrawn_credential_ids_json
                                                        ::pg_catalog.jsonb
                                                )
                                    )
                            )
                          AND (
                                credential_mutation.value->'row'
                                    ->>'sign_count'
                              )::bigint = assertion_evidence.counter
                    )
                THEN
                    RAISE EXCEPTION
                        'authority v9 WebAuthn CAS mutations are incomplete';
                END IF;
            END IF;

            FOR mutation IN
                SELECT planned.value
                FROM pg_catalog.jsonb_array_elements(
                    planner.mutation_plan_json::pg_catalog.jsonb
                ) AS planned(value)
                ORDER BY planned.value->>'table' COLLATE "C",
                    planned.value->>'keyDigest' COLLATE "C",
                    planned.value->>'operation' COLLATE "C"
            LOOP
                IF NOT {closed_record_sql('mutation')}
                    OR (mutation->>'operation'
                        IN ('INSERT', 'UPDATE', 'DELETE')) IS NOT TRUE
                    OR pg_catalog.jsonb_typeof(mutation->'key')
                        IS DISTINCT FROM 'object'
                    OR NOT EXISTS (
                        SELECT 1
                        FROM {namespace}.
                            policy_authority_operation_mutation_templates
                            AS template
                        WHERE template.operation = capability.operation
                          AND template.template_id =
                                mutation->>'templateId'
                          AND template.table_name = mutation->>'table'
                          AND template.mutation =
                                mutation->>'operation'
                          AND template.predicate_kind =
                                'exact-primary-key-and-full-row-cas-v1'
                          AND template.cardinality = 1
                          AND template.operation_manifest_digest =
                                capability.operation_manifest_digest
                          AND template.template_json =
                                {namespace}.
                                    serverware_policy_authority_wire_json(
                                        template.template_json
                                            ::pg_catalog.jsonb
                                    )
                          AND template.source_revision =
                                '{source_revision}'
                    )
                    OR NOT EXISTS (
                        SELECT 1
                        FROM {namespace}.
                            policy_authority_query_dependency_manifests
                            AS dependency
                        WHERE dependency.operation = capability.operation
                          AND dependency.table_name =
                                mutation->>'table'
                          AND dependency.write_access = 1
                    )
                    OR NOT EXISTS (
                        SELECT 1
                        FROM pg_catalog.jsonb_array_elements(
                            planner.selected_business_rows_json
                                ::pg_catalog.jsonb
                        ) AS selected(value)
                        WHERE selected.value->>'table' =
                                mutation->>'table'
                          AND selected.value->'key' =
                                mutation->'key'
                    )
                    OR mutation->>'keyDigest' IS DISTINCT FROM
                        {namespace}.
                            serverware_policy_authority_domain_digest(
                                'serverware.policyAuthorityBusinessKey/v1',
                                mutation->>'table',
                                {namespace}.
                                    serverware_policy_authority_wire_json(
                                        mutation->'key'
                                    )
                            )
                THEN
                    RAISE EXCEPTION
                        'authority v9 mutation is outside the write set';
                END IF;
                SELECT dependency.key_columns_json::pg_catalog.jsonb
                INTO STRICT key_columns
                FROM {namespace}.
                    policy_authority_query_dependency_manifests
                    AS dependency
                WHERE dependency.operation = capability.operation
                  AND dependency.table_name = mutation->>'table';
                {apply_mutation_sql(namespace)}
            END LOOP;

            now_epoch_ns := pg_catalog.floor(
                EXTRACT(
                    EPOCH FROM pg_catalog.clock_timestamp()
                ) * 1000000000
            );
            IF now_epoch_ns >= capability.deadline_epoch_ns
                OR now_epoch_ns >= execution_envelope.deadline_epoch_ns
                OR now_epoch_ns >= planner.deadline_epoch_ns
            THEN
                RAISE EXCEPTION
                    'authority v9 commit deadline expired';
            END IF;
            SELECT {namespace}.serverware_policy_authority_wire_json(
                pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'table', roots.table_name,
                        'rootRevision', roots.root_revision,
                        'rootDigest', roots.root_digest,
                        'leafCount', roots.leaf_count
                    )
                    ORDER BY roots.table_name COLLATE "C"
                )
            )
            INTO root_set_after_json
            FROM {namespace}.policy_authority_authenticated_table_roots
                AS roots
            WHERE roots.table_name IN (
                SELECT dependency.table_name
                FROM {namespace}.
                    policy_authority_query_dependency_manifests
                    AS dependency
                WHERE dependency.operation = capability.operation
            );
            root_set_after_digest :=
                {namespace}.serverware_policy_authority_domain_digest(
                    'serverware.policyAuthorityRootSet/v1',
                    COALESCE(root_set_after_json, '[]')
                );
            {assert_root_transition_after_sql(namespace)}
            receipt_value := pg_catalog.jsonb_build_object(
                'schema',
                    'serverware.policyAuthorityWriterCommitReceipt/v2',
                'capabilityId', capability.capability_id,
                'envelopeId', execution_envelope.envelope_id,
                'plannerTransactionId',
                    planner.planner_transaction_id,
                'authorizationProjectionDigest',
                    authorization_projection.
                        authorization_projection_digest,
                'operation', capability.operation,
                'handlerName', capability.handler_name,
                'requestDigest', capability.request_digest,
                'resultDigest', computed_result_digest,
                'authorityRootSetBeforeDigest',
                    root_set_before_digest,
                'authorityRootSetAfterDigest',
                    root_set_after_digest,
                'authoritySnapshotDigest',
                    computed_authority_snapshot_digest,
                'operationManifestDigest',
                    capability.operation_manifest_digest,
                'queryManifestDigest',
                    capability.query_manifest_digest,
                'witnessReservationDigest',
                    capability.witness_reservation_digest,
                'witnessSequence', capability.witness_sequence,
                'deadlineMonotonicNs',
                    capability.deadline_monotonic_ns,
                'fence', capability.fence,
                'committedAtEpochNs', now_epoch_ns::bigint,
                'sourceRevision', '{source_revision}'
            );
            receipt_json :=
                {namespace}.serverware_policy_authority_wire_json(
                    receipt_value
                );
            receipt_digest :=
                {namespace}.serverware_policy_authority_domain_digest(
                    'serverware.policyAuthorityWriterCommitReceipt/v2',
                    receipt_json
                );
            INSERT INTO {namespace}.policy_authority_consumed_envelopes (
                envelope_id, parent_envelope_id, purpose, operation,
                request_digest, deadline_monotonic_ns, fence,
                consumed_at_epoch_ns, witness_receipt_digest
            ) VALUES (
                execution_envelope.envelope_id,
                execution_envelope.parent_envelope_id,
                execution_envelope.purpose,
                capability.operation,
                capability.request_digest,
                capability.deadline_monotonic_ns,
                capability.fence,
                now_epoch_ns::bigint,
                capability.witness_reservation_digest
            );
            INSERT INTO {namespace}.policy_authority_writer_receipts (
                commit_receipt_digest, capability_id, envelope_id,
                operation, handler_name, request_digest,
                result_json, result_digest,
                authority_root_set_before_digest,
                authority_root_set_after_digest,
                operation_manifest_digest, query_manifest_digest,
                witness_reservation_digest, witness_sequence,
                deadline_monotonic_ns, fence,
                committed_at_epoch_ns, source_revision
            ) VALUES (
                receipt_digest, capability.capability_id,
                execution_envelope.envelope_id,
                capability.operation, capability.handler_name,
                capability.request_digest, canonical_result,
                computed_result_digest,
                root_set_before_digest, root_set_after_digest,
                capability.operation_manifest_digest,
                capability.query_manifest_digest,
                capability.witness_reservation_digest,
                capability.witness_sequence,
                capability.deadline_monotonic_ns,
                capability.fence, now_epoch_ns::bigint,
                '{source_revision}'
            );
            UPDATE {namespace}.policy_authority_writer_capabilities
            SET status = 'committed',
                writer_token_digest =
                    {namespace}.
                        serverware_policy_authority_domain_digest(
                            'serverware.policyAuthorityV9TransactionToken/v1',
                            capability.capability_id,
                            execution_envelope.envelope_id,
                            planner.planner_transaction_id
                        ),
                reserved_at_epoch_ns = now_epoch_ns::bigint,
                reserved_transaction_id = pg_catalog.txid_current(),
                result_digest = computed_result_digest,
                commit_receipt_digest = receipt_digest,
                committed_at_epoch_ns = now_epoch_ns::bigint
            WHERE capability_id = capability.capability_id
              AND status = 'issued';
            GET DIAGNOSTICS matched_count = ROW_COUNT;
            IF matched_count <> 1 THEN
                RAISE EXCEPTION
                    'authority v9 capability consume CAS failed';
            END IF;
            UPDATE {namespace}.policy_authority_planner_transactions
            SET status = 'consumed',
                exact_response_base64url =
                    supplied_exact_result_base64url,
                exact_response_bytes_digest =
                    'sha256:' || pg_catalog.encode(
                        pg_catalog.sha256(result_bytes), 'hex'
                    ),
                exact_response_byte_count =
                    pg_catalog.octet_length(result_bytes),
                terminal_receipt_json = receipt_json,
                terminal_receipt_digest = receipt_digest,
                terminal_at_epoch_ns = now_epoch_ns::bigint
            WHERE planner_transaction_id =
                    planner.planner_transaction_id
              AND status = 'planned';
            GET DIAGNOSTICS matched_count = ROW_COUNT;
            IF matched_count <> 1 THEN
                RAISE EXCEPTION
                    'authority v9 planner consume CAS failed';
            END IF;
            UPDATE {namespace}.policy_authority_execution_envelopes
            SET status = 'committed',
                exact_response_base64url =
                    supplied_exact_result_base64url,
                exact_response_bytes_digest =
                    'sha256:' || pg_catalog.encode(
                        pg_catalog.sha256(result_bytes), 'hex'
                    ),
                exact_response_byte_count =
                    pg_catalog.octet_length(result_bytes),
                result_digest = computed_result_digest,
                terminal_receipt_json = receipt_json,
                terminal_receipt_digest = receipt_digest,
                terminal_at_epoch_ns = now_epoch_ns::bigint
            WHERE envelope_id = execution_envelope.envelope_id
              AND status = 'reserved';
            GET DIAGNOSTICS matched_count = ROW_COUNT;
            IF matched_count <> 1 THEN
                RAISE EXCEPTION
                    'authority v9 envelope commit CAS failed';
            END IF;
            RETURN receipt_json;
        END;
        $serverware_execute_v9$;

        {wrapper_definitions}

        CREATE OR REPLACE FUNCTION {namespace}.
            serverware_policy_authority_apply_verified(
                operation text,
                request_json text,
                request_digest text,
                verifier_response_json text,
                verifier_response_digest text
            )
        RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        VOLATILE
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $serverware_legacy_apply_v9$
        BEGIN
            RAISE EXCEPTION
                'legacy authority apply is disabled by schema v9';
        END;
        $serverware_legacy_apply_v9$;

        CREATE OR REPLACE FUNCTION {namespace}.
            serverware_policy_authority_begin_controlled_writer(
                supplied_capability_id text,
                supplied_operation text,
                supplied_request_digest text,
                supplied_operation_manifest_digest text,
                supplied_deadline_monotonic_ns bigint,
                supplied_fence bigint
            )
        RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        VOLATILE
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $serverware_legacy_begin_v9$
        BEGIN
            RAISE EXCEPTION
                'legacy controlled writer begin is disabled by schema v9';
        END;
        $serverware_legacy_begin_v9$;

        CREATE OR REPLACE FUNCTION {namespace}.
            serverware_policy_authority_finish_controlled_writer(
                supplied_writer_token text,
                supplied_capability_id text,
                supplied_result_json text,
                supplied_result_digest text,
                supplied_deadline_monotonic_ns bigint,
                supplied_fence bigint
            )
        RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        VOLATILE
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $serverware_legacy_finish_v9$
        BEGIN
            RAISE EXCEPTION
                'legacy controlled writer finish is disabled by schema v9';
        END;
        $serverware_legacy_finish_v9$;
        """
    )


def _require_postgres_connection(connection: Any) -> Any:
    postgres_connection = _db_value("PostgresMetadataConnection")
    if not isinstance(connection, postgres_connection):
        raise _db_value("MetadataStoreError")(
            "authority v9 APIs require the measured PostgreSQL facade"
        )
    return connection.raw_connection


def _require_serializable(raw: Any) -> None:
    with raw.cursor() as cursor:
        row = cursor.execute("SHOW transaction_isolation").fetchone()
    if row is None or row["transaction_isolation"] != "serializable":
        raise _db_value("MetadataStoreError")(
            "authority v9 write APIs require SERIALIZABLE"
        )


def _require_database_role(raw: Any, expected_role: str) -> None:
    with raw.cursor() as cursor:
        row = cursor.execute(
            "SELECT current_user AS current_role, "
            "session_user AS session_role, "
            "current_setting('transaction_read_only') AS read_only, "
            "current_setting('transaction_deferrable') AS deferrable"
        ).fetchone()
    if (
        row is None
        or row["current_role"] != expected_role
        or row["session_role"] != expected_role
        or row["read_only"] != "off"
        or row["deferrable"] != "off"
    ):
        raise _db_value("MetadataStoreError")(
            "authority database role or writer transaction mode is not exact"
        )


def _require_planner_writer(connection: Any) -> Any:
    raw = _require_postgres_connection(connection)
    _require_serializable(raw)
    _require_database_role(
        raw,
        _db_value("_METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE"),
    )
    return raw


def _require_executor(connection: Any) -> Any:
    raw = _require_postgres_connection(connection)
    _require_serializable(raw)
    _require_database_role(
        raw,
        _db_value("_METADATA_STORE_AUTHORITY_EXECUTOR_ROLE"),
    )
    return raw


def _require_fresh_deadline(
    *,
    deadline_monotonic_ns: int,
    deadline_epoch_ns: int,
    reserved_at_epoch_ns: int,
) -> None:
    if (
        any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in (
                deadline_monotonic_ns,
                deadline_epoch_ns,
                reserved_at_epoch_ns,
            )
        )
    ):
        raise ValueError("authority v9 deadline is not integral")
    now_monotonic_ns = time.monotonic_ns()
    now_epoch_ns = time.time_ns()
    maximum_age_ns = int(
        _db_value("_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_AGE_NS")
    )
    maximum_skew_ns = int(
        _db_value("_POLICY_AUTHORITY_VERIFIER_MAX_CLOCK_SKEW_NS")
    )
    monotonic_remaining = deadline_monotonic_ns - now_monotonic_ns
    epoch_remaining = deadline_epoch_ns - now_epoch_ns
    if (
        reserved_at_epoch_ns > now_epoch_ns + maximum_skew_ns
        or now_epoch_ns - reserved_at_epoch_ns > maximum_age_ns
        or monotonic_remaining <= 0
        or epoch_remaining <= 0
        or monotonic_remaining > maximum_age_ns
        or epoch_remaining > maximum_age_ns + maximum_skew_ns
        or abs(monotonic_remaining - epoch_remaining) > maximum_skew_ns
    ):
        raise ValueError(
            "authority v9 deadline binding is stale or inconsistent"
        )


def compute_authority_v9_snapshot_digest(
    *,
    operation: str,
    operation_id: str,
    request_digest: str,
    query_manifest_digest: str,
    authority_root_set_before_digest: str,
    authorization_projection_digest: str,
    selected_business_rows_digest: str,
    mutation_plan_digest: str,
    root_transition_digest: str,
) -> str:
    authority_contract.operation_spec(operation)
    values = (
        request_digest,
        query_manifest_digest,
        authority_root_set_before_digest,
        authorization_projection_digest,
        selected_business_rows_digest,
        mutation_plan_digest,
        root_transition_digest,
    )
    if (
        operation_id != _operation_id(operation, request_digest)
        or any(not _is_sha256(value) for value in values)
    ):
        raise ValueError("authority v9 snapshot binding is invalid")
    return _digest(
        "serverware.policyAuthoritySnapshot/v3",
        operation.encode("utf-8"),
        operation_id.encode("utf-8"),
        request_digest.encode("utf-8"),
        query_manifest_digest.encode("utf-8"),
        authority_root_set_before_digest.encode("utf-8"),
        authorization_projection_digest.encode("utf-8"),
        selected_business_rows_digest.encode("utf-8"),
        mutation_plan_digest.encode("utf-8"),
        root_transition_digest.encode("utf-8"),
    )


def compute_authority_v9_result_digest(exact_result_bytes: bytes) -> str:
    if (
        len(exact_result_bytes) < 2
        or len(exact_result_bytes) > authority_contract.MAX_RESULT_BYTES
    ):
        raise ValueError("authority v9 result exceeds its byte bound")
    try:
        exact_result_json = exact_result_bytes.decode("ascii")
        exact_result = json.loads(exact_result_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("authority v9 result is not canonical JSON") from exc
    if _canonical(exact_result) != exact_result_json:
        raise ValueError("authority v9 result is not exact")
    return _digest(
        "serverware.policyAuthorityControlledWriterResult/v2",
        exact_result_bytes,
    )


def derive_authority_v9_plan_contract(
    *,
    operation: str,
    request: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive the closed plan contract without acquiring a writer session."""
    if operation not in authority_transition_registry.PLANNABLE_OPERATIONS:
        raise ValueError(
            "authority v9 operation has no exact typed transition program"
        )
    spec = authority_contract.operation_spec(operation)
    selectors = authority_contract.extract_selectors(operation, request)
    return {
        "schema": "serverware.policyAuthorityPlanDerivation/v1",
        "operation": operation,
        "operationContractDigest":
            authority_contract.OPERATION_MANIFEST_DIGEST,
        "executorFunction":
            authority_contract.SQL_GRANT_MANIFEST[operation][
                "executorHandler"
            ],
        "executorIdentityArguments":
            list(authority_contract.EXECUTOR_ARGUMENT_TYPES),
        "selectors": {
            table: list(values)
            for table, values in sorted(selectors.items())
        },
        "mutationTemplates": [
            dict(template)
            for template in spec["mutationTemplates"]
        ],
    }


def reserve_authority_execution_envelope(
    *,
    envelope_id: str,
    parent_envelope_id: str | None,
    operation: str,
    operation_id: str,
    request_digest: str,
    capability_id: str,
    planner_transaction_id: str,
    authorization_projection_digest: str,
    exact_request_bytes: bytes,
    deadline_monotonic_ns: int,
    deadline_epoch_ns: int,
    fence: int,
    reserved_at_epoch_ns: int,
    connection: Any,
) -> dict[str, Any]:
    if operation not in authority_transition_registry.PLANNABLE_OPERATIONS:
        raise ValueError(
            "authority v9 operation has no exact typed transition program"
        )
    authority_contract.operation_spec(operation)
    _require_fresh_deadline(
        deadline_monotonic_ns=deadline_monotonic_ns,
        deadline_epoch_ns=deadline_epoch_ns,
        reserved_at_epoch_ns=reserved_at_epoch_ns,
    )
    if (
        len(exact_request_bytes) < 2
        or len(exact_request_bytes) > authority_contract.MAX_REQUEST_BYTES
        or not _is_sha256(request_digest)
        or not _is_sha256(capability_id)
        or not _is_sha256(planner_transaction_id)
        or not _is_sha256(authorization_projection_digest)
        or operation_id != _operation_id(operation, request_digest)
        or deadline_monotonic_ns < 1
        or deadline_epoch_ns <= reserved_at_epoch_ns
        or fence < 1
    ):
        raise ValueError("authority v9 envelope binding is invalid")
    try:
        exact_request_json = exact_request_bytes.decode("ascii")
        exact_request = json.loads(exact_request_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("authority v9 request is not canonical JSON") from exc
    if (
        not isinstance(exact_request, dict)
        or _canonical(exact_request) != exact_request_json
        or exact_request.get("operation") != operation
        or exact_request.get("operationId") != operation_id
        or exact_request.get("requestDigest") != request_digest
    ):
        raise ValueError("authority v9 request binding is not exact")
    raw = _require_planner_writer(connection)
    request_base64url = _b64url(exact_request_bytes)
    request_bytes_digest = "sha256:" + hashlib.sha256(
        exact_request_bytes
    ).hexdigest()
    with raw.cursor() as cursor:
        cursor.execute(
            "INSERT INTO serverware_metadata."
            "policy_authority_execution_envelopes ("
            "envelope_id, parent_envelope_id, purpose, operation, "
            "operation_id, request_digest, capability_id, "
            "planner_transaction_id, authorization_projection_digest, "
            "operation_contract_digest, exact_request_base64url, "
            "exact_request_bytes_digest, exact_request_byte_count, "
            "deadline_monotonic_ns, deadline_epoch_ns, fence, status, "
            "reserved_at_epoch_ns, source_revision"
            ") VALUES (%s, %s, 'execute-v9', %s, %s, %s, %s, %s, %s, "
            "%s, %s, %s, %s, %s, %s, %s, 'reserved', %s, %s) "
            "ON CONFLICT (envelope_id) DO NOTHING",
            (
                envelope_id,
                parent_envelope_id,
                operation,
                operation_id,
                request_digest,
                capability_id,
                planner_transaction_id,
                authorization_projection_digest,
                authority_contract.OPERATION_MANIFEST_DIGEST,
                request_base64url,
                request_bytes_digest,
                len(exact_request_bytes),
                deadline_monotonic_ns,
                deadline_epoch_ns,
                fence,
                reserved_at_epoch_ns,
                authority_contract.SOURCE_REVISION,
            ),
        )
        row = cursor.execute(
            "SELECT * FROM serverware_metadata."
            "policy_authority_execution_envelopes "
            "WHERE envelope_id = %s FOR UPDATE",
            (envelope_id,),
        ).fetchone()
    expected = {
        "operation": operation,
        "operation_id": operation_id,
        "request_digest": request_digest,
        "capability_id": capability_id,
        "planner_transaction_id": planner_transaction_id,
        "authorization_projection_digest":
            authorization_projection_digest,
        "operation_contract_digest":
            authority_contract.OPERATION_MANIFEST_DIGEST,
        "exact_request_base64url": request_base64url,
        "exact_request_bytes_digest": request_bytes_digest,
        "exact_request_byte_count": len(exact_request_bytes),
        "deadline_monotonic_ns": deadline_monotonic_ns,
        "deadline_epoch_ns": deadline_epoch_ns,
        "fence": fence,
        "source_revision": authority_contract.SOURCE_REVISION,
    }
    if row is None or any(row[key] != value for key, value in expected.items()):
        raise _db_value("MetadataStoreError")(
            "authority v9 envelope identity was reused"
        )
    return dict(row)


def terminalize_authority_execution_envelope(
    *,
    envelope_id: str,
    status: str,
    exact_response_bytes: bytes,
    terminal_at_epoch_ns: int,
    failure_code: str | None,
    connection: Any,
) -> dict[str, Any]:
    raise _db_value("MetadataStoreError")(
        "split envelope terminalization is disabled; use "
        "fail_authority_v9_transaction"
    )
    if status != "failed" or not failure_code:
        raise ValueError(
            "only the executor transaction may commit an authority envelope"
        )
    if (
        len(exact_response_bytes) < 2
        or len(exact_response_bytes) > authority_contract.MAX_RESULT_BYTES
    ):
        raise ValueError("authority failure response exceeds its byte bound")
    try:
        failure_response_json = exact_response_bytes.decode("ascii")
        failure_response = json.loads(failure_response_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "authority failure response is not canonical JSON"
        ) from exc
    if _canonical(failure_response) != failure_response_json:
        raise ValueError("authority failure response is not exact")
    raw = _require_planner_writer(connection)
    response_base64url = _b64url(exact_response_bytes)
    response_bytes_digest = "sha256:" + hashlib.sha256(
        exact_response_bytes
    ).hexdigest()
    failure_digest = _digest(
        "serverware.policyAuthorityExecutionFailure/v1",
        failure_code.encode("utf-8"),
    )
    result_digest = None
    with raw.cursor() as cursor:
        updated = cursor.execute(
            "UPDATE serverware_metadata."
            "policy_authority_execution_envelopes SET status = %s, "
            "exact_response_base64url = %s, "
            "exact_response_bytes_digest = %s, "
            "exact_response_byte_count = %s, result_digest = %s, "
            "failure_code = %s, failure_digest = %s, "
            "terminal_at_epoch_ns = %s "
            "WHERE envelope_id = %s AND status = 'reserved'",
            (
                status,
                response_base64url,
                response_bytes_digest,
                len(exact_response_bytes),
                result_digest,
                failure_code,
                failure_digest,
                terminal_at_epoch_ns,
                envelope_id,
            ),
        )
        row = cursor.execute(
            "SELECT * FROM serverware_metadata."
            "policy_authority_execution_envelopes "
            "WHERE envelope_id = %s",
            (envelope_id,),
        ).fetchone()
    if updated.rowcount not in (0, 1) or row is None:
        raise _db_value("MetadataStoreError")(
            "authority v9 envelope terminal CAS failed"
        )
    expected = {
        "status": status,
        "exact_response_base64url": response_base64url,
        "exact_response_bytes_digest": response_bytes_digest,
        "exact_response_byte_count": len(exact_response_bytes),
        "result_digest": result_digest,
        "failure_code": failure_code,
        "failure_digest": failure_digest,
        "terminal_at_epoch_ns": terminal_at_epoch_ns,
    }
    if any(row[key] != value for key, value in expected.items()):
        raise _db_value("MetadataStoreError")(
            "authority v9 envelope terminal retry is not exact"
        )
    return dict(row)


def read_authority_execution_response(
    *, envelope_id: str, connection: Any
) -> bytes | None:
    raw = _require_postgres_connection(connection)
    with raw.cursor() as cursor:
        row = cursor.execute(
            "SELECT status, exact_response_base64url, "
            "exact_response_bytes_digest, exact_response_byte_count "
            "FROM serverware_metadata."
            "policy_authority_execution_envelopes "
            "WHERE envelope_id = %s",
            (envelope_id,),
        ).fetchone()
    if row is None or row["status"] == "reserved":
        return None
    encoded = str(row["exact_response_base64url"])
    payload = base64.urlsafe_b64decode(
        encoded + "=" * ((4 - len(encoded) % 4) % 4)
    )
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if (
        digest != row["exact_response_bytes_digest"]
        or len(payload) != row["exact_response_byte_count"]
        or len(payload) > authority_contract.MAX_RESULT_BYTES
    ):
        raise _db_value("MetadataStoreError")(
            "authority v9 stored response bytes changed"
        )
    return payload


def reserve_authority_planner_transaction(
    *,
    planner_transaction_id: str,
    operation: str,
    operation_id: str,
    request_digest: str,
    request: Mapping[str, Any],
    capability_id: str,
    query_manifest_digest: str,
    selected_business_rows: list[dict[str, Any]],
    mutation_plan: list[dict[str, Any]],
    work_units: int,
    authority_root_set_before_digest: str,
    planner_session_identity_digest: str,
    planner_measurement_digest: str,
    planner_attestation_receipt_digest: str,
    deadline_monotonic_ns: int,
    deadline_epoch_ns: int,
    fence: int,
    reserved_at_epoch_ns: int,
    connection: Any,
) -> dict[str, Any]:
    if operation not in authority_transition_registry.PLANNABLE_OPERATIONS:
        raise ValueError(
            "authority v9 operation has no exact typed transition program"
        )
    spec = authority_contract.operation_spec(operation)
    _require_fresh_deadline(
        deadline_monotonic_ns=deadline_monotonic_ns,
        deadline_epoch_ns=deadline_epoch_ns,
        reserved_at_epoch_ns=reserved_at_epoch_ns,
    )
    if (
        not isinstance(request, Mapping)
        or not isinstance(selected_business_rows, list)
        or not isinstance(mutation_plan, list)
        or len(selected_business_rows) > int(spec["maximumQueryRows"])
        or len(mutation_plan) > int(spec["maximumMutations"])
        or not isinstance(work_units, int)
        or isinstance(work_units, bool)
        or not 1 <= work_units <= int(spec["maximumWorkUnits"])
        or any(
            not isinstance(entry, dict)
            for entry in (*selected_business_rows, *mutation_plan)
        )
        or not _is_sha256(request_digest)
        or not _is_sha256(capability_id)
        or not _is_sha256(planner_transaction_id)
        or not _is_sha256(query_manifest_digest)
        or not _is_sha256(authority_root_set_before_digest)
        or not _is_sha256(planner_session_identity_digest)
        or not _is_sha256(planner_measurement_digest)
        or not _is_sha256(planner_attestation_receipt_digest)
        or operation_id != _operation_id(operation, request_digest)
        or deadline_monotonic_ns < 1
        or deadline_epoch_ns <= reserved_at_epoch_ns
        or fence < 1
    ):
        raise ValueError("planner row or mutation set is outside its bound")
    expected_selectors = authority_contract.extract_selectors(
        operation, request
    )
    selected_tables = {
        str(entry.get("table")) for entry in selected_business_rows
    }
    if selected_tables - (
        set(spec["businessReads"])
        | set(spec["businessWrites"])
        | set(spec["authorizationReads"])
    ):
        raise ValueError(
            "planner selected rows exceed the query and authorization closure"
        )
    mutation_tables = {
        str(entry.get("table")) for entry in mutation_plan
    }
    if mutation_tables - set(spec["businessWrites"]):
        raise ValueError("planner mutations exceed the business write closure")
    expected_selector_pairs = sorted(
        (table, value)
        for table, values in expected_selectors.items()
        for value in values
    )
    actual_selector_pairs = sorted(
        (str(entry.get("table")), str(entry.get("contractSelector")))
        for entry in selected_business_rows
        if entry.get("contractSelector") is not None
    )
    selected_keys = {
        (
            str(entry.get("table")),
            _canonical(entry.get("key")),
        )
        for entry in selected_business_rows
    }
    mutation_keys = {
        (
            str(entry.get("table")),
            _canonical(entry.get("key")),
        )
        for entry in mutation_plan
    }
    for entry in mutation_plan:
        try:
            template = authority_contract.mutation_template(
                operation, str(entry.get("templateId"))
            )
        except ValueError as exc:
            raise ValueError(
                "planner mutation template is not allowlisted"
            ) from exc
        if (
            template["table"] != entry.get("table")
            or template["mutation"] != entry.get("operation")
            or template["predicate"]
                != "exact-primary-key-and-full-row-cas-v1"
            or template["cardinality"] != 1
        ):
            raise ValueError(
                "planner mutation does not match its exact template"
            )
    if (
        expected_selector_pairs != actual_selector_pairs
        or selected_business_rows != sorted(
            selected_business_rows,
            key=lambda entry: (
                str(entry.get("table")),
                str(entry.get("keyDigest")),
            ),
        )
        or mutation_plan != sorted(
            mutation_plan,
            key=lambda entry: (
                str(entry.get("table")),
                str(entry.get("keyDigest")),
                str(entry.get("operation")),
            ),
        )
        or len(selected_keys) != len(selected_business_rows)
        or len(mutation_keys) != len(mutation_plan)
        or mutation_keys - selected_keys
        or any(
            set(entry) != {
                "table",
                "key",
                "keyDigest",
                "present",
                "row",
                "contractSelector",
            }
            or not isinstance(entry["key"], dict)
            or not isinstance(entry["present"], bool)
            or (
                entry["present"]
                and not isinstance(entry["row"], dict)
            )
            or (not entry["present"] and entry["row"] is not None)
            or entry["keyDigest"] != _digest(
                "serverware.policyAuthorityBusinessKey/v1",
                str(entry["table"]).encode("utf-8"),
                _canonical(entry["key"]).encode("ascii"),
            )
            for entry in selected_business_rows
        )
        or any(
            set(entry) != {
                "templateId",
                "operation",
                "table",
                "key",
                "keyDigest",
                "expectedRow",
                "row",
            }
            or entry["operation"] not in {"INSERT", "UPDATE", "DELETE"}
            or not isinstance(entry["key"], dict)
            or entry["keyDigest"] != _digest(
                "serverware.policyAuthorityBusinessKey/v1",
                str(entry["table"]).encode("utf-8"),
                _canonical(entry["key"]).encode("ascii"),
            )
            or (
                entry["operation"] == "INSERT"
                and (
                    entry["expectedRow"] is not None
                    or not isinstance(entry["row"], dict)
                )
            )
            or (
                entry["operation"] == "UPDATE"
                and (
                    not isinstance(entry["expectedRow"], dict)
                    or not isinstance(entry["row"], dict)
                )
            )
            or (
                entry["operation"] == "DELETE"
                and (
                    not isinstance(entry["expectedRow"], dict)
                    or entry["row"] is not None
                )
            )
            for entry in mutation_plan
        )
    ):
        raise ValueError("planner selector or mutation closure is not exact")
    selected_json = _canonical(selected_business_rows)
    mutation_json = _canonical(mutation_plan)
    if (
        len(selected_json.encode("ascii")) > authority_contract.MAX_REQUEST_BYTES
        or len(mutation_json.encode("ascii"))
            > authority_contract.MAX_RESULT_BYTES
    ):
        raise ValueError("planner canonical set exceeds its byte bound")
    raw = _require_planner_writer(connection)
    values = (
        planner_transaction_id,
        operation,
        operation_id,
        request_digest,
        capability_id,
        authority_contract.OPERATION_MANIFEST_DIGEST,
        query_manifest_digest,
        selected_json,
        _digest(
            "serverware.policyAuthoritySelectedBusinessRows/v1",
            selected_json.encode("ascii"),
        ),
        mutation_json,
        _digest(
            "serverware.policyAuthorityMutationPlan/v3",
            mutation_json.encode("ascii"),
        ),
        work_units,
        authority_root_set_before_digest,
        planner_session_identity_digest,
        planner_measurement_digest,
        planner_attestation_receipt_digest,
        deadline_monotonic_ns,
        deadline_epoch_ns,
        fence,
        reserved_at_epoch_ns,
        authority_contract.SOURCE_REVISION,
    )
    with raw.cursor() as cursor:
        cursor.execute(
            "INSERT INTO serverware_metadata."
            "policy_authority_planner_transactions ("
            "planner_transaction_id, operation, operation_id, "
            "request_digest, capability_id, operation_contract_digest, "
            "query_manifest_digest, selected_business_rows_json, "
            "selected_business_rows_digest, mutation_plan_json, "
            "mutation_plan_digest, work_units, "
            "authority_root_set_before_digest, "
            "planner_session_identity_digest, "
            "planner_measurement_digest, "
            "planner_attestation_receipt_digest, "
            "deadline_monotonic_ns, deadline_epoch_ns, fence, status, "
            "reserved_at_epoch_ns, source_revision"
            ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
            "%s, %s, %s, %s, %s, %s, %s, %s, 'reserved', %s, %s) "
            "ON CONFLICT (planner_transaction_id) DO NOTHING",
            values,
        )
        row = cursor.execute(
            "SELECT * FROM serverware_metadata."
            "policy_authority_planner_transactions "
            "WHERE planner_transaction_id = %s FOR UPDATE",
            (planner_transaction_id,),
        ).fetchone()
    if row is None or tuple(row[key] for key in (
        "planner_transaction_id",
        "operation",
        "operation_id",
        "request_digest",
        "capability_id",
        "operation_contract_digest",
        "query_manifest_digest",
        "selected_business_rows_json",
        "selected_business_rows_digest",
        "mutation_plan_json",
        "mutation_plan_digest",
        "work_units",
        "authority_root_set_before_digest",
        "planner_session_identity_digest",
        "planner_measurement_digest",
        "planner_attestation_receipt_digest",
        "deadline_monotonic_ns",
        "deadline_epoch_ns",
        "fence",
        "reserved_at_epoch_ns",
        "source_revision",
    )) != values:
        raise _db_value("MetadataStoreError")(
            "authority v9 planner transaction identity was reused"
        )
    return dict(row)


def persist_webauthn_assertion_evidence(
    *, evidence: Mapping[str, Any], connection: Any
) -> str:
    required = {
        "operation",
        "operationId",
        "requestDigest",
        "capabilityId",
        "challengeId",
        "challengeDigest",
        "clientChallengeDigest",
        "credentialRecordId",
        "credentialId",
        "credentialPolicyDigest",
        "authenticatorDataBase64url",
        "authenticatorDataDigest",
        "clientDataJSONBase64url",
        "clientDataJSONDigest",
        "signatureBase64url",
        "signatureDigest",
        "rpId",
        "rpIdHashDigest",
        "origin",
        "flags",
        "userPresent",
        "userVerified",
        "priorCounter",
        "counter",
        "trustHighWaterDigest",
        "metadataPublicationSequence",
        "verifierSessionIdentityDigest",
        "verifierMeasurementDigest",
        "verifierAttestationReceiptDigest",
        "verifiedAssertionReceiptDigest",
        "verifierSignatureBase64url",
        "verifierSignatureDigest",
        "verifiedAtEpochNs",
        "expiresAtEpochNs",
    }
    if set(evidence) != required:
        raise ValueError("WebAuthn assertion evidence is not closed")
    spec = authority_contract.operation_spec(str(evidence["operation"]))
    if not bool(spec["assertionRequired"]):
        raise ValueError("operation does not accept WebAuthn assertion evidence")
    if evidence["userPresent"] is not True or evidence["userVerified"] is not True:
        raise ValueError("WebAuthn user presence and verification are required")
    authenticator_data = _decode_b64url(
        evidence["authenticatorDataBase64url"],
        label="WebAuthn authenticator data",
    )
    client_data_json_bytes = _decode_b64url(
        evidence["clientDataJSONBase64url"],
        label="WebAuthn client data JSON",
    )
    signature = _decode_b64url(
        evidence["signatureBase64url"],
        label="WebAuthn signature",
    )
    try:
        client_data = json.loads(client_data_json_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("WebAuthn client data JSON is invalid") from exc
    if (
        len(authenticator_data) < 37
        or not isinstance(client_data, dict)
        or client_data.get("type") != "webauthn.get"
        or client_data.get("origin") != evidence["origin"]
        or client_data.get("crossOrigin", False) is not False
        or not isinstance(client_data.get("challenge"), str)
    ):
        raise ValueError("WebAuthn assertion ceremony binding is invalid")
    challenge_bytes = _decode_b64url(
        client_data["challenge"],
        label="WebAuthn challenge",
    )
    flags = authenticator_data[32]
    sign_count = int.from_bytes(authenticator_data[33:37], "big")
    rp_id_hash = hashlib.sha256(
        str(evidence["rpId"]).encode("utf-8")
    ).digest()
    now_epoch_ns = time.time_ns()
    maximum_age_ns = int(
        _db_value("_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_AGE_NS")
    )
    maximum_skew_ns = int(
        _db_value("_POLICY_AUTHORITY_VERIFIER_MAX_CLOCK_SKEW_NS")
    )
    expected_digests = {
        "authenticatorDataDigest":
            "sha256:" + hashlib.sha256(authenticator_data).hexdigest(),
        "clientDataJSONDigest":
            "sha256:" + hashlib.sha256(client_data_json_bytes).hexdigest(),
        "signatureDigest":
            "sha256:" + hashlib.sha256(signature).hexdigest(),
        "clientChallengeDigest":
            "sha256:" + hashlib.sha256(challenge_bytes).hexdigest(),
        "rpIdHashDigest": "sha256:" + rp_id_hash.hex(),
    }
    if (
        any(evidence[field] != value for field, value in expected_digests.items())
        or authenticator_data[:32] != rp_id_hash
        or not isinstance(evidence["flags"], int)
        or isinstance(evidence["flags"], bool)
        or evidence["flags"] != flags
        or flags & 0x05 != 0x05
        or not isinstance(evidence["counter"], int)
        or isinstance(evidence["counter"], bool)
        or evidence["counter"] != sign_count
        or not isinstance(evidence["priorCounter"], int)
        or isinstance(evidence["priorCounter"], bool)
        or evidence["priorCounter"] < 0
        or sign_count <= evidence["priorCounter"]
        or not isinstance(evidence["metadataPublicationSequence"], int)
        or isinstance(evidence["metadataPublicationSequence"], bool)
        or not isinstance(evidence["verifiedAtEpochNs"], int)
        or isinstance(evidence["verifiedAtEpochNs"], bool)
        or not isinstance(evidence["expiresAtEpochNs"], int)
        or isinstance(evidence["expiresAtEpochNs"], bool)
        or evidence["verifiedAtEpochNs"] > now_epoch_ns + maximum_skew_ns
        or evidence["expiresAtEpochNs"] <= now_epoch_ns
        or evidence["expiresAtEpochNs"]
            <= evidence["verifiedAtEpochNs"]
        or evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"]
            > maximum_age_ns
        or evidence["metadataPublicationSequence"] < 1
        or evidence["operationId"] != _digest(
            "serverware.policyAuthorityOperation/v2",
            str(evidence["operation"]).encode("utf-8"),
            str(evidence["requestDigest"]).encode("utf-8"),
        )
        or any(
            not _is_sha256(evidence[field])
            for field in (
                "requestDigest",
                "capabilityId",
                "challengeDigest",
                "credentialPolicyDigest",
                "trustHighWaterDigest",
                "verifierSessionIdentityDigest",
                "verifierMeasurementDigest",
                "verifierAttestationReceiptDigest",
                "verifiedAssertionReceiptDigest",
            )
        )
    ):
        raise ValueError("WebAuthn assertion evidence digest is not exact")
    _verify_pinned_verifier_envelope(
        evidence,
        domain=(
            "serverware."
            "policyAuthorityVerifiedWebAuthnAssertionReceipt/v1"
        ),
        receipt_digest_field="verifiedAssertionReceiptDigest",
    )
    evidence_json = _canonical(dict(evidence))
    if len(evidence_json.encode("ascii")) > authority_contract.MAX_REQUEST_BYTES:
        raise ValueError("WebAuthn assertion evidence exceeds its byte bound")
    evidence_digest = _digest(
        "serverware.policyAuthorityWebAuthnAssertionEvidence/v1",
        evidence_json.encode("ascii"),
    )
    raw = _require_planner_writer(connection)
    columns = (
        "operation",
        "operation_id",
        "request_digest",
        "capability_id",
        "challenge_id",
        "challenge_digest",
        "client_challenge_digest",
        "credential_record_id",
        "credential_id",
        "credential_policy_digest",
        "authenticator_data_base64url",
        "authenticator_data_digest",
        "client_data_json_base64url",
        "client_data_json_digest",
        "signature_base64url",
        "signature_digest",
        "rp_id",
        "rp_id_hash_digest",
        "origin",
        "flags",
        "user_present",
        "user_verified",
        "prior_counter",
        "counter",
        "trust_high_water_digest",
        "metadata_publication_sequence",
        "verifier_session_identity_digest",
        "verifier_measurement_digest",
        "verifier_attestation_receipt_digest",
        "verified_assertion_receipt_digest",
        "evidence_json",
        "verified_at_epoch_ns",
        "expires_at_epoch_ns",
        "source_revision",
    )
    values = (
        evidence["operation"],
        evidence["operationId"],
        evidence["requestDigest"],
        evidence["capabilityId"],
        evidence["challengeId"],
        evidence["challengeDigest"],
        evidence["clientChallengeDigest"],
        evidence["credentialRecordId"],
        evidence["credentialId"],
        evidence["credentialPolicyDigest"],
        evidence["authenticatorDataBase64url"],
        evidence["authenticatorDataDigest"],
        evidence["clientDataJSONBase64url"],
        evidence["clientDataJSONDigest"],
        evidence["signatureBase64url"],
        evidence["signatureDigest"],
        evidence["rpId"],
        evidence["rpIdHashDigest"],
        evidence["origin"],
        evidence["flags"],
        1,
        1,
        evidence["priorCounter"],
        evidence["counter"],
        evidence["trustHighWaterDigest"],
        evidence["metadataPublicationSequence"],
        evidence["verifierSessionIdentityDigest"],
        evidence["verifierMeasurementDigest"],
        evidence["verifierAttestationReceiptDigest"],
        evidence["verifiedAssertionReceiptDigest"],
        evidence_json,
        evidence["verifiedAtEpochNs"],
        evidence["expiresAtEpochNs"],
        authority_contract.SOURCE_REVISION,
    )
    with raw.cursor() as cursor:
        cursor.execute(
            "INSERT INTO serverware_metadata."
            "policy_authority_webauthn_assertion_evidence ("
            "assertion_evidence_digest, "
            + ", ".join(columns)
            + ") VALUES ("
            + ", ".join(["%s"] * (len(columns) + 1))
            + ") ON CONFLICT (assertion_evidence_digest) DO NOTHING",
            (evidence_digest, *values),
        )
        row = cursor.execute(
            "SELECT "
            + ", ".join(columns)
            + " FROM serverware_metadata."
            "policy_authority_webauthn_assertion_evidence "
            "WHERE assertion_evidence_digest = %s",
            (evidence_digest,),
        ).fetchone()
    if row is None or tuple(row[column] for column in columns) != values:
        raise _db_value("MetadataStoreError")(
            "WebAuthn assertion evidence retry is not exact"
        )
    return evidence_digest


def persist_authorization_projection(
    *, projection: Mapping[str, Any], connection: Any
) -> str:
    required = {
        "plannerTransactionId",
        "operation",
        "operationId",
        "requestDigest",
        "capabilityId",
        "authorizationReads",
        "sourceRows",
        "sourceHighWaterDigest",
        "approverPolicyDigest",
        "assertionEvidenceDigest",
        "verifierSessionIdentityDigest",
        "verifierMeasurementDigest",
        "verifierAttestationReceiptDigest",
        "createdAtEpochNs",
        "expiresAtEpochNs",
    }
    if set(projection) != required:
        raise ValueError("authorization projection is not closed")
    spec = authority_contract.operation_spec(str(projection["operation"]))
    if (
        not _is_sha256(projection["requestDigest"])
        or not _is_sha256(projection["capabilityId"])
        or not _is_sha256(projection["plannerTransactionId"])
        or projection["operationId"] != _operation_id(
            str(projection["operation"]),
            str(projection["requestDigest"]),
        )
    ):
        raise ValueError("authorization projection operation binding is invalid")
    if not isinstance(projection["authorizationReads"], list):
        raise ValueError("authorization projection reads are not an array")
    authorization_reads = tuple(projection["authorizationReads"])
    if (
        any(not isinstance(value, str) for value in authorization_reads)
        or authorization_reads != tuple(sorted(authorization_reads))
        or len(set(authorization_reads)) != len(authorization_reads)
        or authorization_reads != spec["authorizationReads"]
    ):
        raise ValueError("authorization projection read closure is not exact")
    source_rows = projection["sourceRows"]
    now_epoch_ns = time.time_ns()
    maximum_age_ns = int(
        _db_value("_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_AGE_NS")
    )
    maximum_skew_ns = int(
        _db_value("_POLICY_AUTHORITY_VERIFIER_MAX_CLOCK_SKEW_NS")
    )
    source_selector_keys = (
        [
            (
                str(row.get("table")),
                _canonical(row.get("selector")),
            )
            for row in source_rows
        ]
        if (
            isinstance(source_rows, list)
            and all(isinstance(row, dict) for row in source_rows)
        )
        else []
    )
    if (
        not isinstance(source_rows, list)
        or len(source_rows) > authority_contract.MAX_QUERY_PROOFS
        or len(source_selector_keys) != len(set(source_selector_keys))
        or source_selector_keys != sorted(source_selector_keys)
        or any(
            not isinstance(row, dict)
            or set(row) != {
                "table",
                "selector",
                "present",
                "row",
                "rowDigest",
            }
            or row["table"] not in authorization_reads
            or not isinstance(row["selector"], dict)
            or not isinstance(row["present"], bool)
            or (
                row["present"]
                and (
                    not isinstance(row["row"], dict)
                    or row["rowDigest"] != _digest(
                        "serverware.policyAuthorityAuthorizationRow/v1",
                        str(row["table"]).encode("utf-8"),
                        _canonical(row["selector"]).encode("ascii"),
                        b"present",
                        _canonical(row["row"]).encode("ascii"),
                    )
                )
            )
            or (
                not row["present"]
                and (
                    row["row"] is not None
                    or row["rowDigest"] != _digest(
                        "serverware.policyAuthorityAuthorizationRow/v1",
                        str(row["table"]).encode("utf-8"),
                        _canonical(row["selector"]).encode("ascii"),
                        b"absent",
                        b"null",
                    )
                )
            )
            for row in source_rows
        )
        or {
            str(row["table"]) for row in source_rows
        } != set(authorization_reads)
        or (
            bool(spec["assertionRequired"])
            != _is_sha256(projection["assertionEvidenceDigest"])
        )
        or (
            bool(spec["approverPolicyRequired"])
            != _is_sha256(projection["approverPolicyDigest"])
        )
        or not _is_sha256(projection["sourceHighWaterDigest"])
        or not _is_sha256(projection["verifierSessionIdentityDigest"])
        or not _is_sha256(projection["verifierMeasurementDigest"])
        or not _is_sha256(projection["verifierAttestationReceiptDigest"])
        or not isinstance(projection["createdAtEpochNs"], int)
        or isinstance(projection["createdAtEpochNs"], bool)
        or not isinstance(projection["expiresAtEpochNs"], int)
        or isinstance(projection["expiresAtEpochNs"], bool)
        or projection["createdAtEpochNs"] > now_epoch_ns + maximum_skew_ns
        or projection["expiresAtEpochNs"] <= now_epoch_ns
        or projection["expiresAtEpochNs"]
            <= projection["createdAtEpochNs"]
        or projection["expiresAtEpochNs"] - projection["createdAtEpochNs"]
            > maximum_age_ns
    ):
        raise ValueError("authorization projection source closure is invalid")
    projection_json = _canonical(dict(projection))
    if len(projection_json.encode("ascii")) > authority_contract.MAX_REQUEST_BYTES:
        raise ValueError("authorization projection exceeds its byte bound")
    projection_digest = _digest(
        "serverware.policyAuthorityAuthorizationProjection/v1",
        projection_json.encode("ascii"),
    )
    authorization_reads_json = _canonical(list(authorization_reads))
    source_rows_json = _canonical(projection["sourceRows"])
    columns = (
        "planner_transaction_id",
        "operation",
        "operation_id",
        "request_digest",
        "capability_id",
        "operation_contract_digest",
        "authorization_reads_json",
        "authorization_reads_digest",
        "source_rows_json",
        "source_rows_digest",
        "source_high_water_digest",
        "approver_policy_digest",
        "assertion_evidence_digest",
        "projection_json",
        "verifier_session_identity_digest",
        "verifier_measurement_digest",
        "verifier_attestation_receipt_digest",
        "created_at_epoch_ns",
        "expires_at_epoch_ns",
        "source_revision",
    )
    values = (
        projection["plannerTransactionId"],
        projection["operation"],
        projection["operationId"],
        projection["requestDigest"],
        projection["capabilityId"],
        authority_contract.OPERATION_MANIFEST_DIGEST,
        authorization_reads_json,
        _digest(
            "serverware.policyAuthorityAuthorizationReads/v1",
            authorization_reads_json.encode("ascii"),
        ),
        source_rows_json,
        _digest(
            "serverware.policyAuthorityAuthorizationRows/v1",
            source_rows_json.encode("ascii"),
        ),
        projection["sourceHighWaterDigest"],
        projection["approverPolicyDigest"],
        projection["assertionEvidenceDigest"],
        projection_json,
        projection["verifierSessionIdentityDigest"],
        projection["verifierMeasurementDigest"],
        projection["verifierAttestationReceiptDigest"],
        projection["createdAtEpochNs"],
        projection["expiresAtEpochNs"],
        authority_contract.SOURCE_REVISION,
    )
    raw = _require_planner_writer(connection)
    with raw.cursor() as cursor:
        cursor.execute(
            "INSERT INTO serverware_metadata."
            "policy_authority_authorization_projections ("
            "authorization_projection_digest, "
            + ", ".join(columns)
            + ") VALUES ("
            + ", ".join(["%s"] * (len(columns) + 1))
            + ") ON CONFLICT (authorization_projection_digest) DO NOTHING",
            (projection_digest, *values),
        )
        row = cursor.execute(
            "SELECT "
            + ", ".join(columns)
            + " FROM serverware_metadata."
            "policy_authority_authorization_projections "
            "WHERE authorization_projection_digest = %s",
            (projection_digest,),
        ).fetchone()
    if row is None or tuple(row[column] for column in columns) != values:
        raise _db_value("MetadataStoreError")(
            "authorization projection retry is not exact"
        )
    return projection_digest


def complete_authority_planner_transaction(
    *,
    planner_transaction_id: str,
    authorization_projection_digest: str,
    exact_plan_bytes: bytes,
    planned_at_epoch_ns: int,
    connection: Any,
) -> dict[str, Any]:
    if len(exact_plan_bytes) > authority_contract.MAX_RESULT_BYTES:
        raise ValueError("authority measured plan exceeds its byte bound")
    try:
        exact_plan_json = exact_plan_bytes.decode("ascii")
        planner_payload = json.loads(exact_plan_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("authority measured plan is not canonical JSON") from exc
    required_payload_fields = {
        "schema",
        "measuredPlan",
        "typedRequest",
        "selectedBusinessRows",
        "mutationPlan",
        "queryMultiproofs",
        "queryMultiproofsDigest",
        "plannerTrace",
        "plannerTraceDigest",
        "authorizationProjection",
        "webauthnEvidence",
        "expectedResult",
        "expectedResultDigest",
        "plannerIdentity",
        "rootTransition",
    }
    required_plan_fields = {
        "schema",
        "plannerTransactionId",
        "operation",
        "operationId",
        "requestDigest",
        "capabilityId",
        "sourceRevision",
        "authoritySchemaVersion",
        "operationContractDigest",
        "operationManifestDigest",
        "handlerContractDigest",
        "queryManifestDigest",
        "selectedBusinessRowsDigest",
        "mutationPlanDigest",
        "workUnits",
        "authorityRootSetBeforeDigest",
        "authorizationProjectionDigest",
        "authoritySnapshotDigest",
        "deadlineMonotonicNs",
        "deadlineEpochNs",
        "fence",
        "rootTransitionDigest",
    }
    plan = (
        planner_payload.get("measuredPlan")
        if isinstance(planner_payload, dict)
        else None
    )
    planner_identity = (
        planner_payload.get("plannerIdentity")
        if isinstance(planner_payload, dict)
        else None
    )
    if (
        len(exact_plan_bytes) < 2
        or not isinstance(planner_payload, dict)
        or set(planner_payload) != required_payload_fields
        or planner_payload.get("schema")
            != "serverware.policyAuthorityPlannerResponse/v3"
        or not isinstance(plan, dict)
        or set(plan) != required_plan_fields
        or plan["schema"]
            != "serverware.policyAuthorityMeasuredPlan/v3"
        or plan.get("operation")
            not in authority_transition_registry.PLANNABLE_OPERATIONS
        or plan.get("sourceRevision")
            != authority_contract.SOURCE_REVISION
        or plan.get("authoritySchemaVersion")
            != authority_contract.SCHEMA_VERSION
        or plan.get("operationContractDigest")
            != authority_contract.OPERATION_MANIFEST_DIGEST
        or plan.get("operationManifestDigest")
            != authority_contract.OPERATION_MANIFEST_DIGEST
        or plan.get("handlerContractDigest")
            != authority_contract.handler_contract_digest(
                str(plan.get("operation"))
            )
        or not isinstance(plan.get("workUnits"), int)
        or isinstance(plan.get("workUnits"), bool)
        or not 1
            <= plan["workUnits"]
            <= int(
                authority_contract.operation_spec(
                    str(plan.get("operation"))
                )["maximumWorkUnits"]
            )
        or not isinstance(planner_identity, dict)
        or set(planner_identity)
            != {
                "sessionIdentityDigest",
                "measurementDigest",
                "attestationReceiptDigest",
            }
        or plan["plannerTransactionId"] != planner_transaction_id
        or plan["authorizationProjectionDigest"]
            != authorization_projection_digest
        or not isinstance(planned_at_epoch_ns, int)
        or isinstance(planned_at_epoch_ns, bool)
        or planned_at_epoch_ns < 1
        or any(
            not _is_sha256(plan[field])
            for field in (
                "plannerTransactionId",
                "requestDigest",
                "capabilityId",
                "operationContractDigest",
                "operationManifestDigest",
                "handlerContractDigest",
                "queryManifestDigest",
                "selectedBusinessRowsDigest",
                "mutationPlanDigest",
                "authorityRootSetBeforeDigest",
                "authorizationProjectionDigest",
                "authoritySnapshotDigest",
                "rootTransitionDigest",
            )
        )
        or any(
            not _is_sha256(planner_payload[field])
            for field in (
                "queryMultiproofsDigest",
                "plannerTraceDigest",
                "expectedResultDigest",
            )
        )
        or any(
            not _is_sha256(planner_identity[field])
            for field in planner_identity
        )
        or _canonical(planner_payload) != exact_plan_json
    ):
        raise ValueError("authority measured plan binding is not exact")
    root_transition = validate_primary_root_transition(
        planner_payload["rootTransition"]
    )
    spec = authority_contract.operation_spec(plan["operation"])
    if (
        {entry["table"] for entry in root_transition["businessBeforeRoots"]}
            != set(spec["businessReads"]) | set(spec["businessWrites"])
        or {entry["table"] for entry in root_transition["authorizationBeforeRoots"]}
            != set(spec["authorizationReads"])
        or primary_root_transition_digest(root_transition)
            != plan["rootTransitionDigest"]
        or _digest(
            "serverware.policyAuthorityRootSet/v1",
            _canonical(root_transition["businessBeforeRoots"]).encode("ascii"),
        ) != plan["authorityRootSetBeforeDigest"]
        or compute_authority_v9_snapshot_digest(
            operation=plan["operation"],
            operation_id=plan["operationId"],
            request_digest=plan["requestDigest"],
            query_manifest_digest=plan["queryManifestDigest"],
            authority_root_set_before_digest=plan["authorityRootSetBeforeDigest"],
            authorization_projection_digest=plan["authorizationProjectionDigest"],
            selected_business_rows_digest=plan["selectedBusinessRowsDigest"],
            mutation_plan_digest=plan["mutationPlanDigest"],
            root_transition_digest=plan["rootTransitionDigest"],
        ) != plan["authoritySnapshotDigest"]
    ):
        raise ValueError("authority measured root transition binding is not exact")
    raw = _require_planner_writer(connection)
    plan_base64url = _b64url(exact_plan_bytes)
    plan_digest = "sha256:" + hashlib.sha256(exact_plan_bytes).hexdigest()
    with raw.cursor() as cursor:
        updated = cursor.execute(
            "UPDATE serverware_metadata."
            "policy_authority_planner_transactions "
            "SET status = 'planned', authorization_projection_digest = %s, "
            "authority_snapshot_digest = %s, "
            "exact_plan_base64url = %s, exact_plan_bytes_digest = %s, "
            "exact_plan_byte_count = %s, planned_at_epoch_ns = %s "
            "WHERE planner_transaction_id = %s AND status = 'reserved'",
            (
                authorization_projection_digest,
                plan["authoritySnapshotDigest"],
                plan_base64url,
                plan_digest,
                len(exact_plan_bytes),
                planned_at_epoch_ns,
                planner_transaction_id,
            ),
        )
        row = cursor.execute(
            "SELECT * FROM serverware_metadata."
            "policy_authority_planner_transactions "
            "WHERE planner_transaction_id = %s",
            (planner_transaction_id,),
        ).fetchone()
    if updated.rowcount not in (0, 1) or row is None:
        raise _db_value("MetadataStoreError")(
            "authority planner completion CAS failed"
        )
    expected = {
        "status": "planned",
        "authorization_projection_digest":
            authorization_projection_digest,
        "authority_snapshot_digest": plan["authoritySnapshotDigest"],
        "exact_plan_base64url": plan_base64url,
        "exact_plan_bytes_digest": plan_digest,
        "exact_plan_byte_count": len(exact_plan_bytes),
    }
    if (
        any(row[key] != value for key, value in expected.items())
        or not isinstance(row["planned_at_epoch_ns"], int)
        or row["planned_at_epoch_ns"] < 1
    ):
        raise _db_value("MetadataStoreError")(
            "authority planner completion retry is not exact"
        )
    plan_to_row = {
        "operation": "operation",
        "operationId": "operation_id",
        "requestDigest": "request_digest",
        "capabilityId": "capability_id",
        "operationContractDigest": "operation_contract_digest",
        "queryManifestDigest": "query_manifest_digest",
        "selectedBusinessRowsDigest":
            "selected_business_rows_digest",
        "mutationPlanDigest": "mutation_plan_digest",
        "workUnits": "work_units",
        "authorityRootSetBeforeDigest":
            "authority_root_set_before_digest",
        "deadlineMonotonicNs": "deadline_monotonic_ns",
        "deadlineEpochNs": "deadline_epoch_ns",
        "fence": "fence",
    }
    if any(
        plan[plan_field] != row[row_field]
        for plan_field, row_field in plan_to_row.items()
    ) or (
        planner_identity["sessionIdentityDigest"]
            != row["planner_session_identity_digest"]
        or planner_identity["measurementDigest"]
            != row["planner_measurement_digest"]
        or planner_identity["attestationReceiptDigest"]
            != row["planner_attestation_receipt_digest"]
    ):
        raise _db_value("MetadataStoreError")(
            "authority measured plan differs from its reservation"
        )
    return dict(row)


def read_authority_planner_payload(
    *,
    planner_transaction_id: str,
    operation_id: str,
    request_digest: str,
    capability_id: str,
    connection: Any,
) -> bytes | None:
    if any(
        not _is_sha256(value)
        for value in (
            planner_transaction_id,
            operation_id,
            request_digest,
            capability_id,
        )
    ):
        raise ValueError("authority planner replay identity is invalid")
    raw = _require_planner_writer(connection)
    with raw.cursor() as cursor:
        row = cursor.execute(
            "SELECT planner_transaction_id, operation_id, request_digest, "
            "capability_id, status, exact_plan_base64url, "
            "exact_plan_bytes_digest, exact_plan_byte_count "
            "FROM serverware_metadata."
            "policy_authority_planner_transactions "
            "WHERE planner_transaction_id = %s",
            (planner_transaction_id,),
        ).fetchone()
    if row is None:
        return None
    if (
        row["planner_transaction_id"] != planner_transaction_id
        or row["operation_id"] != operation_id
        or row["request_digest"] != request_digest
        or row["capability_id"] != capability_id
    ):
        raise _db_value("MetadataStoreError")(
            "authority planner replay identity was reused"
        )
    if row["status"] not in {"planned", "consumed"}:
        raise _db_value("MetadataStoreError")(
            "authority planner replay is not durably planned"
        )
    exact_plan_bytes = _decode_b64url(
        row["exact_plan_base64url"],
        label="authority planner exact payload",
    )
    if (
        len(exact_plan_bytes) != row["exact_plan_byte_count"]
        or "sha256:" + hashlib.sha256(exact_plan_bytes).hexdigest()
            != row["exact_plan_bytes_digest"]
        or len(exact_plan_bytes) > authority_contract.MAX_RESULT_BYTES
    ):
        raise _db_value("MetadataStoreError")(
            "authority planner replay bytes changed"
        )
    return exact_plan_bytes


def fail_authority_planner_transaction(
    *,
    planner_transaction_id: str,
    exact_response_bytes: bytes,
    terminal_at_epoch_ns: int,
    connection: Any,
) -> dict[str, Any]:
    raise _db_value("MetadataStoreError")(
        "split planner terminalization is disabled; use "
        "fail_authority_v9_transaction"
    )


def fail_authority_v9_transaction(
    *,
    capability_id: str,
    envelope_id: str,
    planner_transaction_id: str,
    failure_code: str,
    exact_response_bytes: bytes,
    terminal_at_epoch_ns: int,
    connection: Any,
) -> dict[str, Any]:
    if (
        not _is_sha256(capability_id)
        or not _is_sha256(planner_transaction_id)
        or not isinstance(envelope_id, str)
        or not envelope_id
        or not isinstance(failure_code, str)
        or not failure_code
        or len(failure_code.encode("utf-8")) > 256
        or not isinstance(terminal_at_epoch_ns, int)
        or isinstance(terminal_at_epoch_ns, bool)
        or len(exact_response_bytes) < 2
        or len(exact_response_bytes) > authority_contract.MAX_RESULT_BYTES
    ):
        raise ValueError("authority v9 failure terminal is invalid")
    try:
        response_json = exact_response_bytes.decode("ascii")
        response = json.loads(response_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "authority v9 failure response is not canonical JSON"
        ) from exc
    if _canonical(response) != response_json:
        raise ValueError("authority v9 failure response is not exact")
    response_base64url = _b64url(exact_response_bytes)
    response_digest = (
        "sha256:" + hashlib.sha256(exact_response_bytes).hexdigest()
    )
    failure_digest = _digest(
        "serverware.policyAuthorityExecutionFailure/v2",
        capability_id.encode("ascii"),
        envelope_id.encode("utf-8"),
        planner_transaction_id.encode("ascii"),
        failure_code.encode("utf-8"),
        response_digest.encode("ascii"),
    )
    raw = _require_planner_writer(connection)
    with raw.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM serverware_metadata."
            "policy_authority_fence_heads "
            "WHERE authority_scope = 'controlled-writer' FOR UPDATE"
        ).fetchone()
        capability = cursor.execute(
            "SELECT * FROM serverware_metadata."
            "policy_authority_writer_capabilities "
            "WHERE capability_id = %s FOR UPDATE",
            (capability_id,),
        ).fetchone()
        envelope = cursor.execute(
            "SELECT * FROM serverware_metadata."
            "policy_authority_execution_envelopes "
            "WHERE envelope_id = %s FOR UPDATE",
            (envelope_id,),
        ).fetchone()
        planner = cursor.execute(
            "SELECT * FROM serverware_metadata."
            "policy_authority_planner_transactions "
            "WHERE planner_transaction_id = %s FOR UPDATE",
            (planner_transaction_id,),
        ).fetchone()
        if capability is None or envelope is None or planner is None:
            raise _db_value("MetadataStoreError")(
                "authority v9 failure binding is absent"
            )
        exact_binding = (
            capability["envelope_id"] == envelope_id
            and capability["planner_transaction_id"]
                == planner_transaction_id
            and envelope["capability_id"] == capability_id
            and envelope["planner_transaction_id"]
                == planner_transaction_id
            and planner["capability_id"] == capability_id
        )
        if not exact_binding:
            raise _db_value("MetadataStoreError")(
                "authority v9 failure binding changed"
            )
        if (
            capability["status"] == "failed"
            or envelope["status"] == "failed"
            or planner["status"] == "failed"
        ):
            if not (
                capability["status"] == "failed"
                and envelope["status"] == "failed"
                and planner["status"] == "failed"
                and capability["failure_digest"] == failure_digest
                and envelope["failure_code"] == failure_code
                and envelope["failure_digest"] == failure_digest
                and envelope["exact_response_base64url"]
                    == response_base64url
                and envelope["exact_response_bytes_digest"]
                    == response_digest
                and planner["exact_response_base64url"]
                    == response_base64url
                and planner["exact_response_bytes_digest"]
                    == response_digest
                and envelope["terminal_at_epoch_ns"]
                    == terminal_at_epoch_ns
                and planner["terminal_at_epoch_ns"]
                    == terminal_at_epoch_ns
                and capability["failed_at_epoch_ns"]
                    == terminal_at_epoch_ns
            ):
                raise _db_value("MetadataStoreError")(
                    "authority v9 failure retry is not exact"
                )
            return {
                "status": "failed",
                "failureDigest": failure_digest,
                "exactResponseBytes": exact_response_bytes,
            }
        if (
            capability["status"] != "issued"
            or envelope["status"] != "reserved"
            or planner["status"] not in {"reserved", "planned"}
        ):
            raise _db_value("MetadataStoreError")(
                "authority v9 failure cannot replace a terminal state"
            )
        capability_update = cursor.execute(
            "UPDATE serverware_metadata."
            "policy_authority_writer_capabilities "
            "SET status = 'failed', failure_digest = %s, "
            "failed_at_epoch_ns = %s "
            "WHERE capability_id = %s AND status = 'issued'",
            (failure_digest, terminal_at_epoch_ns, capability_id),
        )
        envelope_update = cursor.execute(
            "UPDATE serverware_metadata."
            "policy_authority_execution_envelopes "
            "SET status = 'failed', exact_response_base64url = %s, "
            "exact_response_bytes_digest = %s, "
            "exact_response_byte_count = %s, failure_code = %s, "
            "failure_digest = %s, terminal_at_epoch_ns = %s "
            "WHERE envelope_id = %s AND status = 'reserved'",
            (
                response_base64url,
                response_digest,
                len(exact_response_bytes),
                failure_code,
                failure_digest,
                terminal_at_epoch_ns,
                envelope_id,
            ),
        )
        planner_update = cursor.execute(
            "UPDATE serverware_metadata."
            "policy_authority_planner_transactions "
            "SET status = 'failed', exact_response_base64url = %s, "
            "exact_response_bytes_digest = %s, "
            "exact_response_byte_count = %s, terminal_at_epoch_ns = %s "
            "WHERE planner_transaction_id = %s "
            "AND status IN ('reserved', 'planned')",
            (
                response_base64url,
                response_digest,
                len(exact_response_bytes),
                terminal_at_epoch_ns,
                planner_transaction_id,
            ),
        )
    if (
        capability_update.rowcount != 1
        or envelope_update.rowcount != 1
        or planner_update.rowcount != 1
    ):
        raise _db_value("MetadataStoreError")(
            "authority v9 atomic failure CAS failed"
        )
    return {
        "status": "failed",
        "failureDigest": failure_digest,
        "exactResponseBytes": exact_response_bytes,
    }


def execute_authority_v9(
    *,
    capability_id: str,
    envelope_id: str,
    planner_transaction_id: str,
    exact_request_bytes: bytes,
    exact_result_bytes: bytes,
    deadline_monotonic_ns: int,
    connection: Any,
) -> str:
    if (
        len(exact_request_bytes) < 2
        or len(exact_request_bytes) > authority_contract.MAX_REQUEST_BYTES
        or len(exact_result_bytes) < 2
        or len(exact_result_bytes) > authority_contract.MAX_RESULT_BYTES
    ):
        raise ValueError("authority v9 exact request or result exceeds its bound")
    try:
        exact_request_json = exact_request_bytes.decode("ascii")
        exact_request = json.loads(exact_request_json)
        exact_result_json = exact_result_bytes.decode("ascii")
        exact_result = json.loads(exact_result_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "authority v9 exact request or result is not canonical JSON"
        ) from exc
    if (
        not isinstance(exact_request, dict)
        or _canonical(exact_request) != exact_request_json
        or _canonical(exact_result) != exact_result_json
        or exact_request.get("operation")
            not in authority_transition_registry.PLANNABLE_OPERATIONS
    ):
        raise ValueError("authority v9 exact request or result is not exact")
    operation = str(exact_request["operation"])
    executor_function = str(
        authority_contract.SQL_GRANT_MANIFEST[operation][
            "executorHandler"
        ]
    )
    raw = _require_executor(connection)
    with raw.cursor() as cursor:
        row = cursor.execute(
            "SELECT serverware_metadata."
            + executor_function
            + "("
            "%s, %s, %s, %s, %s) AS receipt_json",
            (
                capability_id,
                envelope_id,
                planner_transaction_id,
                _b64url(exact_request_bytes),
                _b64url(exact_result_bytes),
            ),
        ).fetchone()
    if row is None or not isinstance(row["receipt_json"], str):
        raise _db_value("MetadataStoreError")(
            "authority v9 executor did not return an exact receipt"
        )
    receipt = json.loads(row["receipt_json"])
    if (
        not isinstance(receipt, dict)
        or _canonical(receipt) != row["receipt_json"]
        or receipt.get("deadlineMonotonicNs")
            != deadline_monotonic_ns
        or receipt.get("sourceRevision")
            != authority_contract.SOURCE_REVISION
    ):
        raise _db_value("MetadataStoreError")(
            "authority v9 executor receipt binding is not exact"
        )
    return row["receipt_json"]


for _compatibility_export in (
    compute_authority_v9_snapshot_digest,
    compute_authority_v9_result_digest,
    derive_authority_v9_plan_contract,
    reserve_authority_execution_envelope,
    terminalize_authority_execution_envelope,
    read_authority_execution_response,
    reserve_authority_planner_transaction,
    persist_webauthn_assertion_evidence,
    persist_authorization_projection,
    complete_authority_planner_transaction,
    read_authority_planner_payload,
    fail_authority_planner_transaction,
    fail_authority_v9_transaction,
    execute_authority_v9,
):
    _compatibility_export.__module__ = "serverware.db"
del _compatibility_export
