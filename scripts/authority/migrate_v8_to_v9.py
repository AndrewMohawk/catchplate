from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import stat
import struct
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_contract
from serverware import db
from serverware.authority_store import executor_v9
from serverware.authority_store import metadata_schema_source
from serverware.authority_store.schema import (
    record_policy_candidate_authority_v8_to_v9_receipt,
    repair_policy_candidate_authority_completed_v9_receipt,
)

_CONTRACT_ID = authority_contract.V8_TO_V9_MIGRATION_CONTRACT_ID
_MIGRATION_NAME = authority_contract.V8_TO_V9_MIGRATION_NAME
_SOURCE_VERSION = 8
_TARGET_VERSION = 9
_ADVISORY_LOCK_ID = 8_711_903_719_009
_MAX_ROW_BYTES = 64 * 1024 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_V9_NEW_TABLES = frozenset(
    {
        "policy_authority_v9_offline_migration_receipts",
        "policy_authority_authorization_dependency_manifests",
        "policy_authority_operation_mutation_templates",
        "policy_authority_webauthn_assertion_evidence",
        "policy_authority_authorization_projections",
        "policy_authority_execution_envelopes",
        "policy_authority_planner_transactions",
        "policy_authority_revocation_retained_plans",
        "policy_authority_revocation_retained_capabilities",
        "policy_authority_bounded_aggregate_states",
        "policy_authority_exact_pages",
        "policy_authority_work_pages",
        "policy_authority_tombstones",
        "policy_authority_opaque_values",
        "policy_authority_external_evidence_receipts",
        "policy_authority_secondary_index_heads",
        "policy_authority_continuations",
        "policy_authority_sealed_values",
        "policy_authority_activation_evidence_bindings",
    }
)
_V9_POPULATED_CONTRACT_TABLES = frozenset(
    {
        "policy_authority_authorization_dependency_manifests",
        "policy_authority_operation_mutation_templates",
    }
)
_MIGRATION_TABLES = tuple(
    sorted(
        (
            set(db._POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES)
            | set(db._POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES)
            | {
                table
                for spec in authority_contract.OPERATIONS.values()
                for field in (
                    "businessReads",
                    "businessWrites",
                    "authorizationReads",
                    "frameworkPreconditions",
                    "frameworkWrites",
                )
                for table in spec[field]
            }
        )
        - _V9_NEW_TABLES
    )
)
_SOURCE_REVISION_TABLES = (
    "policy_authority_writer_receipts",
    "policy_authority_query_dependency_manifests",
    "policy_authority_owner_operations",
    "policy_authority_owner_decisions",
    "policy_activation_finalized_exports",
    "policy_activation_export_issuances",
    "policy_activation_export_authorizations",
)
_TERMINAL_CUSTODY_TABLES = frozenset(
    {
        "policy_authority_schema_contracts",
        "policy_authority_owner_contracts",
        "policy_authority_v9_offline_migration_receipts",
    }
)
_ROW_MUTATION_TABLES = frozenset(
    {
        *_SOURCE_REVISION_TABLES,
        "policy_authority_writer_capabilities",
        "policy_authority_query_dependency_manifests",
        "policy_authority_authenticated_table_roots",
        "policy_authority_authenticated_tree_nodes",
        "policy_authority_authenticated_leaves",
        "policy_authority_authenticated_root_revisions",
        *_TERMINAL_CUSTODY_TABLES,
    }
)
_COUNT_MUTATION_TABLES = frozenset(
    {
        "policy_authority_query_dependency_manifests",
        "policy_authority_authenticated_table_roots",
        "policy_authority_authenticated_tree_nodes",
        "policy_authority_authenticated_leaves",
        "policy_authority_authenticated_root_revisions",
    }
)
_OLD_SOURCE_REVISION = (
    "serverware.policyCandidateAuthoritySource/2026-07-29.18"
)
_NEW_SOURCE_REVISION = authority_contract.SOURCE_REVISION
_LEGACY_COMPLETED_V9_RECEIPT_COLUMNS = (
    ("contract_id", "text", True),
    ("source_version", "bigint", True),
    ("target_version", "bigint", True),
    ("before_manifest_json", "text", True),
    ("before_manifest_digest", "text", True),
    ("before_row_counts_json", "text", True),
    ("before_row_counts_digest", "text", True),
    ("after_manifest_json", "text", True),
    ("after_manifest_digest", "text", True),
    ("after_row_counts_json", "text", True),
    ("after_row_counts_digest", "text", True),
    ("operation_contract_digest", "text", True),
    ("receipt_json", "text", True),
    ("receipt_digest", "text", True),
    ("signer_identity_digest", "text", False),
    ("signature_algorithm", "text", False),
    ("detached_signature", "text", False),
    ("detached_signature_digest", "text", False),
    ("status", "text", True),
    ("completed_at", "text", True),
)
_TARGET_COMPLETED_V9_RECEIPT_COLUMNS = (
    ("contract_id", "text", True),
    ("source_version", "bigint", True),
    ("target_version", "bigint", True),
    ("migration_name", "text", True),
    ("migration_sha256", "text", True),
    ("source_revision", "text", True),
    ("before_manifest_json", "text", True),
    ("before_manifest_digest", "text", True),
    ("before_row_counts_json", "text", True),
    ("before_row_counts_digest", "text", True),
    ("after_manifest_json", "text", True),
    ("after_manifest_digest", "text", True),
    ("after_row_counts_json", "text", True),
    ("after_row_counts_digest", "text", True),
    ("operation_contract_digest", "text", True),
    ("receipt_json", "text", True),
    ("receipt_digest", "text", True),
    ("signer_identity_digest", "text", True),
    ("signer_public_key_base64url", "text", True),
    ("signature_algorithm", "text", True),
    ("detached_signature", "text", True),
    ("detached_signature_digest", "text", True),
    ("status", "text", True),
    ("completed_at", "text", True),
)


class MigrationError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _digest(domain: str, *frames: bytes) -> str:
    hasher = hashlib.sha256()
    domain_bytes = domain.encode("ascii")
    hasher.update(len(domain_bytes).to_bytes(8, "big"))
    hasher.update(domain_bytes)
    for frame in frames:
        hasher.update(len(frame).to_bytes(8, "big"))
        hasher.update(frame)
    return "sha256:" + hasher.hexdigest()


def _require_digest(value: object, *, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(
            character not in "0123456789abcdef"
            for character in value[7:]
        )
    ):
        raise MigrationError(f"{name} is not a SHA-256 digest")
    return value


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_base64url(value: str) -> bytes:
    if not value or any(
        character not in
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in value
    ):
        raise MigrationError("detached signature is not canonical base64url")
    decoded = base64.urlsafe_b64decode(
        value + "=" * ((4 - len(value) % 4) % 4)
    )
    if _encode_base64url(decoded) != value:
        raise MigrationError("detached signature is not canonical base64url")
    return decoded


def _read_descriptor(descriptor: int, *, maximum_bytes: int) -> bytes:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
        or metadata.st_size < 1
        or metadata.st_size > maximum_bytes
    ):
        raise MigrationError("migration descriptor is not immutable and bounded")
    payload = os.pread(descriptor, metadata.st_size, 0)
    after = os.fstat(descriptor)
    if (
        len(payload) != metadata.st_size
        or (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
    ):
        raise MigrationError("migration descriptor changed during read")
    return payload


def _dsn_from_descriptor(descriptor: int) -> str:
    try:
        dsn = _read_descriptor(
            descriptor, maximum_bytes=64 * 1024
        ).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise MigrationError("migration DSN is not UTF-8") from exc
    if not dsn or any(character in dsn for character in "\x00\r\n"):
        raise MigrationError("migration DSN is invalid")
    return dsn


def _table_primary_key(cursor: Any, table: str) -> tuple[str, ...]:
    rows = cursor.execute(
        "SELECT attribute.attname AS column_name "
        "FROM pg_catalog.pg_index AS index_record "
        "JOIN pg_catalog.pg_class AS relation "
        "ON relation.oid = index_record.indrelid "
        "JOIN pg_catalog.pg_namespace AS namespace "
        "ON namespace.oid = relation.relnamespace "
        "JOIN pg_catalog.unnest(index_record.indkey) "
        "WITH ORDINALITY AS key_column(attnum, ordinal) ON true "
        "JOIN pg_catalog.pg_attribute AS attribute "
        "ON attribute.attrelid = relation.oid "
        "AND attribute.attnum = key_column.attnum "
        "WHERE namespace.nspname = 'serverware_metadata' "
        "AND relation.relname = %s "
        "AND index_record.indisprimary "
        "ORDER BY key_column.ordinal",
        (table,),
    ).fetchall()
    columns = tuple(str(row["column_name"]) for row in rows)
    if not columns:
        raise MigrationError(f"allowlisted table {table} has no primary key")
    return columns


def _schema_manifest(cursor: Any, tables: Iterable[str]) -> dict[str, Any]:
    manifest_tables: list[dict[str, Any]] = []
    for table in sorted(tables):
        relation = cursor.execute(
            "SELECT relation.relkind, owner_role.rolname AS owner "
            "FROM pg_catalog.pg_class AS relation "
            "JOIN pg_catalog.pg_namespace AS namespace "
            "ON namespace.oid = relation.relnamespace "
            "JOIN pg_catalog.pg_roles AS owner_role "
            "ON owner_role.oid = relation.relowner "
            "WHERE namespace.nspname = 'serverware_metadata' "
            "AND relation.relname = %s",
            (table,),
        ).fetchall()
        if len(relation) != 1:
            raise MigrationError(
                f"allowlisted table {table} is absent or ambiguous"
            )
        columns = cursor.execute(
            "SELECT attribute.attname AS name, "
            "pg_catalog.format_type("
            "attribute.atttypid, attribute.atttypmod) AS type, "
            "attribute.attnotnull AS not_null, "
            "pg_catalog.pg_get_expr("
            "default_record.adbin, default_record.adrelid) AS default_value "
            "FROM pg_catalog.pg_attribute AS attribute "
            "JOIN pg_catalog.pg_class AS relation "
            "ON relation.oid = attribute.attrelid "
            "JOIN pg_catalog.pg_namespace AS namespace "
            "ON namespace.oid = relation.relnamespace "
            "LEFT JOIN pg_catalog.pg_attrdef AS default_record "
            "ON default_record.adrelid = relation.oid "
            "AND default_record.adnum = attribute.attnum "
            "WHERE namespace.nspname = 'serverware_metadata' "
            "AND relation.relname = %s "
            "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
            "ORDER BY attribute.attnum",
            (table,),
        ).fetchall()
        constraints = cursor.execute(
            "SELECT constraint_record.conname AS name, "
            "constraint_record.contype AS type, "
            "pg_catalog.pg_get_constraintdef("
            "constraint_record.oid, true) AS definition, "
            "constraint_record.convalidated AS validated "
            "FROM pg_catalog.pg_constraint AS constraint_record "
            "JOIN pg_catalog.pg_class AS relation "
            "ON relation.oid = constraint_record.conrelid "
            "JOIN pg_catalog.pg_namespace AS namespace "
            "ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = 'serverware_metadata' "
            "AND relation.relname = %s "
            "ORDER BY constraint_record.conname COLLATE \"C\"",
            (table,),
        ).fetchall()
        indexes = cursor.execute(
            "SELECT index_relation.relname AS name, "
            "pg_catalog.pg_get_indexdef(index_record.indexrelid) "
            "AS definition "
            "FROM pg_catalog.pg_index AS index_record "
            "JOIN pg_catalog.pg_class AS relation "
            "ON relation.oid = index_record.indrelid "
            "JOIN pg_catalog.pg_namespace AS namespace "
            "ON namespace.oid = relation.relnamespace "
            "JOIN pg_catalog.pg_class AS index_relation "
            "ON index_relation.oid = index_record.indexrelid "
            "WHERE namespace.nspname = 'serverware_metadata' "
            "AND relation.relname = %s "
            "ORDER BY index_relation.relname COLLATE \"C\"",
            (table,),
        ).fetchall()
        manifest_tables.append(
            {
                "name": table,
                "kind": relation[0]["relkind"],
                "owner": relation[0]["owner"],
                "primaryKey": list(_table_primary_key(cursor, table)),
                "columns": [dict(row) for row in columns],
                "constraints": [dict(row) for row in constraints],
                "indexes": [dict(row) for row in indexes],
            }
        )
    manifest = {
        "schema":
            "serverware.policyCandidateAuthorityMigrationManifest/v1",
        "namespace": "serverware_metadata",
        "tables": manifest_tables,
    }
    if len(_canonical(manifest)) > _MAX_MANIFEST_BYTES:
        raise MigrationError("migration structure manifest is too large")
    return manifest


def _row_manifest(
    connection: Any,
    cursor: Any,
    tables: Iterable[str],
) -> tuple[dict[str, int], dict[str, str]]:
    counts: dict[str, int] = {}
    digests: dict[str, str] = {}
    for ordinal, table in enumerate(sorted(tables), start=1):
        if table in _TERMINAL_CUSTODY_TABLES:
            continue
        key_columns = _table_primary_key(cursor, table)
        order_sql = ", ".join(
            '"' + column.replace('"', '""') + '"'
            for column in key_columns
        )
        table_sql = '"' + table.replace('"', '""') + '"'
        hasher = hashlib.sha256()
        domain = (
            "serverware.policyCandidateAuthorityMigrationRows/v1:"
            + table
        ).encode("ascii")
        hasher.update(len(domain).to_bytes(8, "big"))
        hasher.update(domain)
        count = 0
        with connection.cursor(
            name=f"serverware_v9_migration_{ordinal}"
        ) as stream:
            stream.itersize = 256
            stream.execute(
                "SELECT pg_catalog.to_jsonb(row_value)::text AS row_json "
                "FROM serverware_metadata."
                + table_sql
                + " AS row_value ORDER BY "
                + order_sql
            )
            for row in stream:
                payload = str(row["row_json"]).encode("utf-8")
                if len(payload) > _MAX_ROW_BYTES:
                    raise MigrationError(
                        f"allowlisted table {table} contains an oversized row"
                    )
                hasher.update(len(payload).to_bytes(8, "big"))
                hasher.update(payload)
                count += 1
        hasher.update(count.to_bytes(8, "big"))
        counts[table] = count
        digests[table] = "sha256:" + hasher.hexdigest()
    return counts, digests


def _completed_retry(
    cursor: Any,
    *,
    migration_sha256: str,
    public_key_file: Path | None,
    expected_signer_digest: str | None,
) -> dict[str, Any] | None:
    present = cursor.execute(
        "SELECT pg_catalog.to_regclass("
        "'serverware_metadata."
        "policy_authority_v9_offline_migration_receipts') "
        "IS NOT NULL AS present"
    ).fetchone()
    if present is None or not bool(present["present"]):
        return None
    rows = cursor.execute(
        "SELECT contract_id, source_version, target_version, "
        "migration_name, migration_sha256, source_revision, "
        "before_manifest_json, before_manifest_digest, "
        "before_row_counts_json, before_row_counts_digest, "
        "after_manifest_json, after_manifest_digest, "
        "after_row_counts_json, after_row_counts_digest, "
        "operation_contract_digest, receipt_json, receipt_digest, "
        "signer_identity_digest, signer_public_key_base64url, "
        "signature_algorithm, "
        "detached_signature, detached_signature_digest, status, completed_at "
        "FROM serverware_metadata."
        "policy_authority_v9_offline_migration_receipts "
        "WHERE contract_id = %s LIMIT 2",
        (_CONTRACT_ID,),
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1 or rows[0]["status"] != "completed":
        raise MigrationError("v9 migration terminal receipt is ambiguous")
    row = rows[0]
    receipt_json = str(row["receipt_json"])
    try:
        receipt = json.loads(receipt_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MigrationError(
            "v9 migration completed receipt is not JSON"
        ) from exc
    canonical_fields = {
        "beforeManifestDigest": (
            authority_contract.MIGRATION_MANIFEST_DIGEST_DOMAIN,
            "before_manifest_json",
            "before_manifest_digest",
        ),
        "beforeRowCountsDigest": (
            authority_contract.MIGRATION_ROWS_DIGEST_DOMAIN,
            "before_row_counts_json",
            "before_row_counts_digest",
        ),
        "afterManifestDigest": (
            authority_contract.MIGRATION_MANIFEST_DIGEST_DOMAIN,
            "after_manifest_json",
            "after_manifest_digest",
        ),
        "afterRowCountsDigest": (
            authority_contract.MIGRATION_ROWS_DIGEST_DOMAIN,
            "after_row_counts_json",
            "after_row_counts_digest",
        ),
    }
    if (
        public_key_file is None
        or expected_signer_digest is None
        or row["contract_id"] != _CONTRACT_ID
        or int(row["source_version"]) != _SOURCE_VERSION
        or int(row["target_version"]) != _TARGET_VERSION
        or row["migration_name"] != _MIGRATION_NAME
        or row["migration_sha256"] != migration_sha256
        or row["source_revision"] != _NEW_SOURCE_REVISION
        or row["operation_contract_digest"]
            != authority_contract.OPERATION_MANIFEST_DIGEST
        or not isinstance(receipt, dict)
        or set(receipt) != {
            "schema",
            "contractId",
            "migrationName",
            "sourceVersion",
            "targetVersion",
            "migrationSha256",
            "sourceRevision",
            "operationContractDigest",
            "signerIdentityDigest",
            "beforeManifestDigest",
            "beforeRowCountsDigest",
            "afterManifestDigest",
            "afterRowCountsDigest",
            "terminal",
            "status",
            "completedAt",
        }
        or _canonical(receipt).decode("ascii") != receipt_json
        or receipt.get("schema")
            != authority_contract.MIGRATION_RECEIPT_SCHEMA
        or receipt.get("contractId") != _CONTRACT_ID
        or receipt.get("migrationName") != _MIGRATION_NAME
        or receipt.get("sourceVersion") != _SOURCE_VERSION
        or receipt.get("targetVersion") != _TARGET_VERSION
        or receipt.get("migrationSha256") != migration_sha256
        or receipt.get("sourceRevision") != _NEW_SOURCE_REVISION
        or receipt.get("operationContractDigest")
            != authority_contract.OPERATION_MANIFEST_DIGEST
        or receipt.get("signerIdentityDigest")
            != row["signer_identity_digest"]
        or receipt.get("terminal") is not True
        or receipt.get("completedAt") != row["completed_at"]
        or receipt.get("status") != "completed"
        or any(
            _canonical(json.loads(str(row[json_column]))).decode("ascii")
                != row[json_column]
            or _digest(
                domain,
                str(row[json_column]).encode("ascii"),
            ) != row[digest_column]
            or receipt.get(receipt_field) != row[digest_column]
            for receipt_field, (
                domain,
                json_column,
                digest_column,
            ) in canonical_fields.items()
        )
        or _digest(
            authority_contract.MIGRATION_RECEIPT_DIGEST_DOMAIN,
            receipt_json.encode("ascii"),
        )
        != row["receipt_digest"]
        or row["signature_algorithm"] != "Ed25519"
    ):
        raise MigrationError("v9 migration completed receipt is not exact")
    (
        public_key_bytes,
        signer_public_key_base64url,
        signer_identity_digest,
    ) = _signer_material(
        public_key_file=public_key_file,
        expected_signer_digest=expected_signer_digest,
    )
    signature = _decode_base64url(str(row["detached_signature"]))
    if (
        len(signature) != 64
        or row["signer_identity_digest"] != signer_identity_digest
        or row["signer_public_key_base64url"]
            != signer_public_key_base64url
        or row["detached_signature_digest"]
            != "sha256:" + hashlib.sha256(signature).hexdigest()
    ):
        raise MigrationError("v9 migration signer binding is not exact")
    signature_message = _digest(
        authority_contract.MIGRATION_RECEIPT_SIGNATURE_DOMAIN,
        receipt_json.encode("ascii"),
    ).encode("ascii")
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature, signature_message
        )
    except Exception as exc:
        raise MigrationError(
            "v9 migration completed receipt signature is invalid"
        ) from exc
    return _terminal_response(
        receipt=receipt,
        receipt_digest=str(row["receipt_digest"]),
        signer_identity_digest=signer_identity_digest,
        signer_public_key_base64url=signer_public_key_base64url,
        signature_algorithm=str(row["signature_algorithm"]),
        detached_signature=str(row["detached_signature"]),
        detached_signature_digest=str(row["detached_signature_digest"]),
    )


def _drop_immutability_triggers(cursor: Any, tables: Iterable[str]) -> None:
    for table in tables:
        triggers = cursor.execute(
            "SELECT trigger_record.tgname AS trigger_name "
            "FROM pg_catalog.pg_trigger AS trigger_record "
            "JOIN pg_catalog.pg_class AS relation "
            "ON relation.oid = trigger_record.tgrelid "
            "JOIN pg_catalog.pg_namespace AS namespace "
            "ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = 'serverware_metadata' "
            "AND relation.relname = %s "
            "AND NOT trigger_record.tgisinternal "
            "AND trigger_record.tgname LIKE "
            "'serverware_%_immutable_%'",
            (table,),
        ).fetchall()
        for trigger in triggers:
            cursor.execute(
                "DROP TRIGGER "
                + '"' + str(trigger["trigger_name"]).replace('"', '""') + '"'
                + " ON serverware_metadata."
                + '"' + table.replace('"', '""') + '"'
            )


def _replace_v8_constraints(cursor: Any) -> None:
    replacements = (
        (_OLD_SOURCE_REVISION, _NEW_SOURCE_REVISION),
        (
            "serverware.policyCandidateAuthoritySchema/v8",
            "serverware.policyCandidateAuthoritySchema/v9",
        ),
        (
            "serverware.policyAuthorityOwnerContract/v1",
            "serverware.policyAuthorityOwnerContract/v2",
        ),
        (
            "serverware_policy_authority_apply_verified",
            "serverware_policy_authority_execute_v9",
        ),
        ("schema_version = 8", "schema_version = 9"),
        ("schema_version = (8)", "schema_version = (9)"),
        (
            "incremental-authenticated-relation-root-v2",
            "incremental-authenticated-relation-root-v3",
        ),
    )
    tables = (
        *_SOURCE_REVISION_TABLES,
        "policy_authority_schema_contracts",
        "policy_authority_owner_contracts",
    )
    for table in tables:
        rows = cursor.execute(
            "SELECT constraint_record.conname AS name, "
            "pg_catalog.pg_get_constraintdef("
            "constraint_record.oid, true) AS definition "
            "FROM pg_catalog.pg_constraint AS constraint_record "
            "JOIN pg_catalog.pg_class AS relation "
            "ON relation.oid = constraint_record.conrelid "
            "JOIN pg_catalog.pg_namespace AS namespace "
            "ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = 'serverware_metadata' "
            "AND relation.relname = %s "
            "AND constraint_record.contype = 'c' "
            "ORDER BY constraint_record.conname COLLATE \"C\"",
            (table,),
        ).fetchall()
        for row in rows:
            old_definition = str(row["definition"])
            new_definition = old_definition
            for old, new in replacements:
                new_definition = new_definition.replace(old, new)
            if new_definition == old_definition:
                continue
            constraint_sql = '"' + str(row["name"]).replace('"', '""') + '"'
            table_sql = '"' + table.replace('"', '""') + '"'
            cursor.execute(
                "ALTER TABLE serverware_metadata."
                + table_sql
                + " DROP CONSTRAINT "
                + constraint_sql
            )
            cursor.execute(
                "ALTER TABLE serverware_metadata."
                + table_sql
                + " ADD CONSTRAINT "
                + constraint_sql
                + " "
                + new_definition
                + " NOT VALID"
            )


def _upgrade_writer_capability_binding(cursor: Any) -> None:
    live = cursor.execute(
        "SELECT 1 FROM serverware_metadata."
        "policy_authority_writer_capabilities "
        "WHERE status IN ('issued', 'reserved') LIMIT 1"
    ).fetchone()
    if live is not None:
        raise MigrationError(
            "v8 has a live writer capability; expire or reconcile it first"
        )
    additions = (
        ("expected_result_digest", "TEXT"),
        ("planner_transaction_id", "TEXT"),
        ("authorization_projection_digest", "TEXT"),
        ("selected_business_rows_digest", "TEXT"),
        ("mutation_plan_digest", "TEXT"),
        ("deadline_epoch_ns", "BIGINT"),
    )
    existing = {
        str(row["attname"])
        for row in cursor.execute(
            "SELECT attribute.attname "
            "FROM pg_catalog.pg_attribute AS attribute "
            "JOIN pg_catalog.pg_class AS relation "
            "ON relation.oid = attribute.attrelid "
            "JOIN pg_catalog.pg_namespace AS namespace "
            "ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = 'serverware_metadata' "
            "AND relation.relname = "
            "'policy_authority_writer_capabilities' "
            "AND attribute.attnum > 0 AND NOT attribute.attisdropped"
        ).fetchall()
    }
    for column, column_type in additions:
        if column in existing:
            raise MigrationError(
                "writer capability has a partial v9 column set"
            )
        cursor.execute(
            "ALTER TABLE serverware_metadata."
            "policy_authority_writer_capabilities ADD COLUMN "
            + '"' + column + '" '
            + column_type
        )
    cursor.execute(
        "UPDATE serverware_metadata."
        "policy_authority_writer_capabilities SET "
        "expected_result_digest = COALESCE(result_digest, "
        "'sha256:' || pg_catalog.encode(pg_catalog.sha256("
        "pg_catalog.convert_to('serverware.v8MigrationResult/' || "
        "capability_id, 'UTF8')), 'hex')), "
        "planner_transaction_id = 'sha256:' || pg_catalog.encode("
        "pg_catalog.sha256(pg_catalog.convert_to("
        "'serverware.v8MigrationPlanner/' || capability_id, 'UTF8')), "
        "'hex'), "
        "authorization_projection_digest = 'sha256:' || "
        "pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to("
        "'serverware.v8MigrationAuthorization/' || capability_id, "
        "'UTF8')), 'hex'), "
        "selected_business_rows_digest = 'sha256:' || "
        "pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to("
        "'serverware.v8MigrationSelection/' || capability_id, "
        "'UTF8')), 'hex'), "
        "mutation_plan_digest = 'sha256:' || pg_catalog.encode("
        "pg_catalog.sha256(pg_catalog.convert_to("
        "'serverware.v8MigrationMutation/' || capability_id, 'UTF8')), "
        "'hex'), "
        "deadline_epoch_ns = expires_at_epoch_ns"
    )
    for column, _ in additions:
        cursor.execute(
            "ALTER TABLE serverware_metadata."
            "policy_authority_writer_capabilities ALTER COLUMN "
            + '"' + column + '" SET NOT NULL'
        )
    cursor.execute(
        "ALTER TABLE serverware_metadata."
        "policy_authority_writer_capabilities ADD CONSTRAINT "
        "policy_authority_writer_capabilities_planner_transaction_id_key "
        "UNIQUE (planner_transaction_id)"
    )
    cursor.execute(
        "ALTER TABLE serverware_metadata."
        "policy_authority_writer_capabilities ADD CONSTRAINT "
        "policy_authority_writer_capability_deadline_epoch "
        "CHECK (deadline_epoch_ns > issued_at_epoch_ns)"
    )
    cursor.execute(
        "ALTER TABLE serverware_metadata."
        "policy_authority_writer_capabilities ADD CONSTRAINT "
        "policy_authority_writer_capability_v9_digests CHECK ("
        "expected_result_digest ~ '^sha256:[0-9a-f]{64}$' "
        "AND planner_transaction_id ~ '^sha256:[0-9a-f]{64}$' "
        "AND authorization_projection_digest ~ '^sha256:[0-9a-f]{64}$' "
        "AND selected_business_rows_digest ~ '^sha256:[0-9a-f]{64}$' "
        "AND mutation_plan_digest ~ '^sha256:[0-9a-f]{64}$')"
    )


def _validate_replaced_constraints(cursor: Any) -> None:
    invalid = cursor.execute(
        "SELECT relation.relname AS table_name, "
        "constraint_record.conname AS constraint_name "
        "FROM pg_catalog.pg_constraint AS constraint_record "
        "JOIN pg_catalog.pg_class AS relation "
        "ON relation.oid = constraint_record.conrelid "
        "JOIN pg_catalog.pg_namespace AS namespace "
        "ON namespace.oid = relation.relnamespace "
        "WHERE namespace.nspname = 'serverware_metadata' "
        "AND relation.relname = ANY(%s) "
        "AND pg_catalog.pg_get_constraintdef("
        "constraint_record.oid, true) LIKE %s",
        (
            list((*_SOURCE_REVISION_TABLES,
                  "policy_authority_schema_contracts",
                  "policy_authority_owner_contracts")),
            "%" + _OLD_SOURCE_REVISION + "%",
        ),
    ).fetchall()
    if invalid:
        raise MigrationError("a v8 source constraint remains")
    for table in (
        *_SOURCE_REVISION_TABLES,
        "policy_authority_schema_contracts",
        "policy_authority_owner_contracts",
    ):
        table_sql = '"' + table.replace('"', '""') + '"'
        constraints = cursor.execute(
            "SELECT constraint_record.conname AS name "
            "FROM pg_catalog.pg_constraint AS constraint_record "
            "JOIN pg_catalog.pg_class AS relation "
            "ON relation.oid = constraint_record.conrelid "
            "JOIN pg_catalog.pg_namespace AS namespace "
            "ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = 'serverware_metadata' "
            "AND relation.relname = %s "
            "AND constraint_record.contype = 'c' "
            "AND NOT constraint_record.convalidated",
            (table,),
        ).fetchall()
        for row in constraints:
            cursor.execute(
                "ALTER TABLE serverware_metadata."
                + table_sql
                + " VALIDATE CONSTRAINT "
                + '"' + str(row["name"]).replace('"', '""') + '"'
            )


def _signer_material(
    *,
    public_key_file: Path | None,
    expected_signer_digest: str | None,
) -> tuple[bytes, str, str]:
    if public_key_file is None or expected_signer_digest is None:
        raise MigrationError(
            "migration signer public key and identity pin are required"
        )
    public_key_bytes = public_key_file.read_bytes()
    if len(public_key_bytes) != 32:
        raise MigrationError("migration signer public key must be raw Ed25519")
    signer_identity_digest = _digest(
        authority_contract.MIGRATION_SIGNER_IDENTITY_DOMAIN,
        public_key_bytes,
    )
    if (
        _require_digest(
            expected_signer_digest,
            name="expected migration signer identity",
        )
        != signer_identity_digest
    ):
        raise MigrationError(
            "migration signer public key does not match its external pin"
        )
    return (
        public_key_bytes,
        _encode_base64url(public_key_bytes),
        signer_identity_digest,
    )


def _signature_material(
    signature_message: bytes,
    *,
    signature_file: Path | None,
    signer_socket: Path | None,
    public_key_bytes: bytes,
) -> tuple[str, str, str]:
    if (signature_file is None) == (signer_socket is None):
        raise MigrationError(
            "choose exactly one external migration signature source"
        )
    if signature_file is not None:
        signature_text = signature_file.read_text(
            encoding="ascii"
        ).strip()
    else:
        assert signer_socket is not None
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(30.0)
            client.connect(str(signer_socket))
            client.sendall(
                struct.pack(">I", len(signature_message))
                + signature_message
            )
            response_size = struct.unpack(
                ">I", _receive_exact(client, 4)
            )[0]
            if response_size < 1 or response_size > 4096:
                raise MigrationError(
                    "external signer response is not bounded"
                )
            signature_text = _receive_exact(
                client, response_size
            ).decode("ascii").strip()
    signature = _decode_base64url(signature_text)
    if len(signature) != 64:
        raise MigrationError("migration receipt signature has the wrong size")
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(signature, signature_message)
    except Exception as exc:
        raise MigrationError("migration receipt signature is invalid") from exc
    signature_digest = "sha256:" + hashlib.sha256(signature).hexdigest()
    return (
        "Ed25519",
        signature_text,
        signature_digest,
    )


def _completed_v9_receipt_column_shape(
    cursor: Any,
) -> tuple[tuple[str, str, bool], ...] | None:
    present = cursor.execute(
        "SELECT pg_catalog.to_regclass("
        "'serverware_metadata."
        "policy_authority_v9_offline_migration_receipts') "
        "IS NOT NULL AS present"
    ).fetchone()
    if present is None or not bool(present["present"]):
        return None
    columns = cursor.execute(
        "SELECT attribute.attname AS column_name, "
        "pg_catalog.format_type("
        "attribute.atttypid, attribute.atttypmod"
        ") AS data_type, "
        "attribute.attnotnull AS not_null, "
        "attribute.attgenerated AS generated_kind, "
        "attribute.attidentity AS identity_kind, "
        "pg_catalog.pg_get_expr("
        "default_record.adbin, default_record.adrelid"
        ") AS default_expression "
        "FROM pg_catalog.pg_attribute AS attribute "
        "JOIN pg_catalog.pg_class AS relation "
        "ON relation.oid = attribute.attrelid "
        "JOIN pg_catalog.pg_namespace AS namespace "
        "ON namespace.oid = relation.relnamespace "
        "LEFT JOIN pg_catalog.pg_attrdef AS default_record "
        "ON default_record.adrelid = relation.oid "
        "AND default_record.adnum = attribute.attnum "
        "WHERE namespace.nspname = 'serverware_metadata' "
        "AND relation.relname = "
        "'policy_authority_v9_offline_migration_receipts' "
        "AND relation.relkind = 'r' "
        "AND attribute.attnum > 0 "
        "AND NOT attribute.attisdropped "
        "ORDER BY attribute.attnum"
    ).fetchall()
    if not columns or any(
        str(column["generated_kind"]) != ""
        or str(column["identity_kind"]) != ""
        or column["default_expression"] is not None
        for column in columns
    ):
        raise MigrationError(
            "v9 migration receipt table has an unrecognized column shape"
        )
    return tuple(
        (
            str(column["column_name"]),
            str(column["data_type"]),
            bool(column["not_null"]),
        )
        for column in columns
    )


def _completed_v9_repair_receipt(
    cursor: Any,
    *,
    migration_sha256: str,
    signer_public_key: bytes,
    signer_identity_digest: str,
) -> dict[str, Any] | None:
    version_rows = cursor.execute(
        "SELECT version FROM serverware_metadata."
        "serverware_store_migrations "
        "WHERE migration = 'policy_candidate_authority' LIMIT 2"
    ).fetchall()
    column_shape = _completed_v9_receipt_column_shape(cursor)
    if column_shape is None or column_shape == (
        _TARGET_COMPLETED_V9_RECEIPT_COLUMNS
    ):
        return None
    if column_shape != _LEGACY_COMPLETED_V9_RECEIPT_COLUMNS:
        raise MigrationError(
            "v9 migration receipt table has an unrecognized column shape"
        )
    if len(version_rows) != 1 or int(version_rows[0]["version"]) != 9:
        raise MigrationError(
            "legacy completed-v9 receipt exists without exact schema v9"
        )
    # This narrow historical receipt repair cannot adopt newer retained
    # evidence. Current completed retries return above and undergo the full
    # recorded-contract validation in migrate(), without reinstalling tables.
    retained = cursor.execute(
        "SELECT pg_catalog.to_regclass(%s) IS NOT NULL AS present",
        ("serverware_metadata." + authority_contract.REVOCATION_RETAINED_TABLE,),
    ).fetchone()
    if retained is None or retained["present"] is not False:
        raise MigrationError(
            "retained revocation storage requires a separately reviewed migration"
        )
    legacy_columns = tuple(
        column_name
        for column_name, _data_type, _not_null
        in _LEGACY_COMPLETED_V9_RECEIPT_COLUMNS
    )
    rows = cursor.execute(
        "SELECT "
        + ", ".join(legacy_columns)
        + " FROM serverware_metadata."
        "policy_authority_v9_offline_migration_receipts "
        "WHERE contract_id = %s LIMIT 2",
        (_CONTRACT_ID,),
    ).fetchall()
    if len(rows) != 1:
        raise MigrationError(
            "legacy completed-v9 migration receipt is missing or ambiguous"
        )
    row = rows[0]
    digest_bindings = (
        (
            "before_manifest_json",
            "before_manifest_digest",
            authority_contract.MIGRATION_MANIFEST_DIGEST_DOMAIN,
        ),
        (
            "before_row_counts_json",
            "before_row_counts_digest",
            authority_contract.MIGRATION_ROWS_DIGEST_DOMAIN,
        ),
        (
            "after_manifest_json",
            "after_manifest_digest",
            authority_contract.MIGRATION_MANIFEST_DIGEST_DOMAIN,
        ),
        (
            "after_row_counts_json",
            "after_row_counts_digest",
            authority_contract.MIGRATION_ROWS_DIGEST_DOMAIN,
        ),
    )
    try:
        for json_column, digest_column, domain in digest_bindings:
            document = str(row[json_column])
            parsed = json.loads(document)
            canonical = _canonical(parsed).decode("ascii")
            if (
                not isinstance(parsed, dict)
                or canonical != document
                or row[digest_column]
                != _digest(domain, canonical.encode("ascii"))
            ):
                raise MigrationError(
                    "legacy completed-v9 migration evidence is not exact"
                )
        legacy_receipt_json = str(row["receipt_json"])
        legacy_receipt = json.loads(legacy_receipt_json)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise MigrationError(
            "legacy completed-v9 migration evidence is not canonical JSON"
        ) from exc
    legacy_receipt_fields = {
        "contractId",
        "sourceVersion",
        "targetVersion",
        "sourceRevision",
        "operationContractDigest",
        "beforeManifestDigest",
        "beforeRowCountsDigest",
        "afterManifestDigest",
        "afterRowCountsDigest",
        "status",
    }
    completed_at = row["completed_at"]
    legacy_signature = _decode_base64url(str(row["detached_signature"]))
    if (
        row["contract_id"] != _CONTRACT_ID
        or row["source_version"] != _SOURCE_VERSION
        or row["target_version"] != _TARGET_VERSION
        or row["operation_contract_digest"]
            != authority_contract.OPERATION_MANIFEST_DIGEST
        or row["status"] != "completed"
        or not isinstance(completed_at, str)
        or not completed_at
        or len(completed_at.encode("utf-8")) > 256
        or any(character in completed_at for character in "\x00\r\n")
        or not isinstance(legacy_receipt, dict)
        or set(legacy_receipt) != legacy_receipt_fields
        or _canonical(legacy_receipt).decode("ascii") != legacy_receipt_json
        or legacy_receipt.get("contractId") != _CONTRACT_ID
        or legacy_receipt.get("sourceVersion") != _SOURCE_VERSION
        or legacy_receipt.get("targetVersion") != _TARGET_VERSION
        or legacy_receipt.get("sourceRevision") != _NEW_SOURCE_REVISION
        or legacy_receipt.get("operationContractDigest")
            != authority_contract.OPERATION_MANIFEST_DIGEST
        or legacy_receipt.get("beforeManifestDigest")
            != row["before_manifest_digest"]
        or legacy_receipt.get("beforeRowCountsDigest")
            != row["before_row_counts_digest"]
        or legacy_receipt.get("afterManifestDigest")
            != row["after_manifest_digest"]
        or legacy_receipt.get("afterRowCountsDigest")
            != row["after_row_counts_digest"]
        or legacy_receipt.get("status") != "completed"
        or row["receipt_digest"]
            != _digest(
                authority_contract.MIGRATION_RECEIPT_DIGEST_DOMAIN,
                legacy_receipt_json.encode("ascii"),
            )
        or row["signer_identity_digest"] != signer_identity_digest
        or row["signature_algorithm"] != "Ed25519"
        or len(legacy_signature) != 64
        or row["detached_signature_digest"]
            != "sha256:" + hashlib.sha256(legacy_signature).hexdigest()
    ):
        raise MigrationError(
            "legacy completed-v9 migration receipt is not exact"
        )
    legacy_signature_message = _digest(
        authority_contract.MIGRATION_RECEIPT_SIGNATURE_DOMAIN,
        legacy_receipt_json.encode("ascii"),
    ).encode("ascii")
    try:
        Ed25519PublicKey.from_public_bytes(signer_public_key).verify(
            legacy_signature,
            legacy_signature_message,
        )
    except Exception as exc:
        raise MigrationError(
            "legacy completed-v9 migration receipt signature is invalid"
        ) from exc
    receipt = {
        "schema": authority_contract.MIGRATION_RECEIPT_SCHEMA,
        "contractId": _CONTRACT_ID,
        "migrationName": _MIGRATION_NAME,
        "sourceVersion": _SOURCE_VERSION,
        "targetVersion": _TARGET_VERSION,
        "migrationSha256": migration_sha256,
        "sourceRevision": _NEW_SOURCE_REVISION,
        "operationContractDigest":
            authority_contract.OPERATION_MANIFEST_DIGEST,
        "signerIdentityDigest": signer_identity_digest,
        "beforeManifestDigest": row["before_manifest_digest"],
        "beforeRowCountsDigest": row["before_row_counts_digest"],
        "afterManifestDigest": row["after_manifest_digest"],
        "afterRowCountsDigest": row["after_row_counts_digest"],
        "terminal": True,
        "completedAt": completed_at,
        "status": "completed",
    }
    receipt_json = _canonical(receipt).decode("ascii")
    return {
        "receipt": receipt,
        "receiptJson": receipt_json,
        "receiptDigest": _digest(
            authority_contract.MIGRATION_RECEIPT_DIGEST_DOMAIN,
            receipt_json.encode("ascii"),
        ),
    }


def _terminal_response(
    *,
    receipt: Mapping[str, Any],
    receipt_digest: str,
    signer_identity_digest: str,
    signer_public_key_base64url: str,
    signature_algorithm: str,
    detached_signature: str,
    detached_signature_digest: str,
) -> dict[str, Any]:
    return {
        "receipt": dict(receipt),
        "receiptDigest": receipt_digest,
        "signerIdentityDigest": signer_identity_digest,
        "signerPublicKeyBase64Url": signer_public_key_base64url,
        "signatureAlgorithm": signature_algorithm,
        "detachedSignature": detached_signature,
        "detachedSignatureDigest": detached_signature_digest,
    }


def _receive_exact(client: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = client.recv(remaining)
        if not chunk:
            raise MigrationError("external signer closed early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def migrate(
    *,
    dsn_descriptor: int,
    migration_sha256: str,
    signature_file: Path | None,
    signer_socket: Path | None,
    public_key_file: Path | None,
    expected_signer_digest: str | None,
) -> dict[str, Any]:
    migration_sha256 = _require_digest(
        migration_sha256, name="migration source digest"
    )
    (
        signer_public_key,
        signer_public_key_base64url,
        signer_identity_digest,
    ) = _signer_material(
        public_key_file=public_key_file,
        expected_signer_digest=expected_signer_digest,
    )
    psycopg, dict_row = db._metadata_psycopg()
    connection = psycopg.connect(
        _dsn_from_descriptor(dsn_descriptor),
        row_factory=dict_row,
        autocommit=False,
    )
    try:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
                )
                cursor.execute(
                    "SET LOCAL search_path TO "
                    "serverware_metadata, pg_catalog, pg_temp"
                )
                cursor.execute("SET LOCAL lock_timeout = '5s'")
                cursor.execute("SET LOCAL statement_timeout = '0'")
                cursor.execute(
                    "SELECT pg_catalog.pg_advisory_xact_lock(%s)",
                    (_ADVISORY_LOCK_ID,),
                )
                repair_receipt = _completed_v9_repair_receipt(
                    cursor,
                    migration_sha256=migration_sha256,
                    signer_public_key=signer_public_key,
                    signer_identity_digest=signer_identity_digest,
                )
        if repair_receipt is not None:
            receipt = repair_receipt["receipt"]
            receipt_json = str(repair_receipt["receiptJson"])
            receipt_digest = str(repair_receipt["receiptDigest"])
            signature_message = _digest(
                authority_contract.MIGRATION_RECEIPT_SIGNATURE_DOMAIN,
                receipt_json.encode("ascii"),
            ).encode("ascii")
            (
                signature_algorithm,
                detached_signature,
                detached_signature_digest,
            ) = _signature_material(
                signature_message,
                signature_file=signature_file,
                signer_socket=signer_socket,
                public_key_bytes=signer_public_key,
            )
            wrapped = db.PostgresMetadataConnection(connection)
            if wrapped.in_transaction:
                raise MigrationError(
                    "completed-v9 repair connection is not idle"
                )
            repaired = (
                repair_policy_candidate_authority_completed_v9_receipt(
                    migration_sha256=migration_sha256,
                    signer_public_key_base64url=(
                        signer_public_key_base64url
                    ),
                    detached_signature=detached_signature,
                    source_schema_program=(
                        metadata_schema_source.metadata_schema_source()
                    ),
                    connection=wrapped,
                )
            )
            if (
                not isinstance(repaired, Mapping)
                or set(repaired)
                    != {
                        "contractId",
                        "receiptDigest",
                        "status",
                        "exactReplay",
                    }
                or repaired.get("contractId") != _CONTRACT_ID
                or repaired.get("receiptDigest") != receipt_digest
                or repaired.get("status") != "completed"
                or not isinstance(repaired.get("exactReplay"), bool)
            ):
                raise MigrationError(
                    "completed-v9 repair did not persist the exact receipt"
                )
            return _terminal_response(
                receipt=receipt,
                receipt_digest=receipt_digest,
                signer_identity_digest=signer_identity_digest,
                signer_public_key_base64url=(
                    signer_public_key_base64url
                ),
                signature_algorithm=signature_algorithm,
                detached_signature=detached_signature,
                detached_signature_digest=detached_signature_digest,
            )
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
                )
                cursor.execute(
                    "SET LOCAL search_path TO "
                    "serverware_metadata, pg_catalog, pg_temp"
                )
                cursor.execute("SET LOCAL lock_timeout = '5s'")
                cursor.execute("SET LOCAL statement_timeout = '0'")
                cursor.execute(
                    "SELECT pg_catalog.pg_advisory_xact_lock(%s)",
                    (_ADVISORY_LOCK_ID,),
                )
                retry = _completed_retry(
                    cursor,
                    migration_sha256=migration_sha256,
                    public_key_file=public_key_file,
                    expected_signer_digest=expected_signer_digest,
                )
                version_row = cursor.execute(
                    "SELECT version FROM serverware_metadata."
                    "serverware_store_migrations "
                    "WHERE migration = 'policy_candidate_authority' "
                    "FOR UPDATE"
                ).fetchone()
                if retry is not None:
                    if version_row is None or int(version_row["version"]) != 9:
                        raise MigrationError(
                            "completed receipt exists without schema v9"
                        )
                    db._validate_policy_candidate_authority_structure(
                        db.PostgresMetadataConnection(connection),
                        require_recorded_contract=True,
                        source_schema_program=(
                            metadata_schema_source.metadata_schema_source()
                        ),
                    )
                    contract_receipts = cursor.execute(
                        "SELECT offline_migration_receipt_digest "
                        "FROM serverware_metadata."
                        "policy_authority_schema_contracts "
                        "WHERE schema_version = 9 LIMIT 2"
                    ).fetchall()
                    if (
                        len(contract_receipts) != 1
                        or contract_receipts[0][
                            "offline_migration_receipt_digest"
                        ]
                            != retry["receiptDigest"]
                    ):
                        raise MigrationError(
                            "completed-v9 schema contract receipt changed"
                        )
                    return retry
                if version_row is None or int(version_row["version"]) != 8:
                    raise MigrationError(
                        "offline migration accepts exactly schema v8"
                    )
                contract = cursor.execute(
                    "SELECT contract_id, source_revision "
                    "FROM serverware_metadata."
                    "policy_authority_schema_contracts "
                    "WHERE schema_version = 8 FOR UPDATE"
                ).fetchall()
                if (
                    len(contract) != 1
                    or contract[0]["contract_id"]
                    != "serverware.policyCandidateAuthoritySchema/v8"
                    or contract[0]["source_revision"]
                    != _OLD_SOURCE_REVISION
                ):
                    raise MigrationError("source schema-v8 contract is not exact")
                existing_tables = tuple(
                    table
                    for table in _MIGRATION_TABLES
                    if cursor.execute(
                        "SELECT pg_catalog.to_regclass(%s) IS NOT NULL "
                        "AS present",
                        ("serverware_metadata." + table,),
                    ).fetchone()["present"]
                )
                if existing_tables != _MIGRATION_TABLES:
                    missing = sorted(set(_MIGRATION_TABLES) - set(existing_tables))
                    raise MigrationError(
                        "schema v8 is missing allowlisted tables: "
                        + ", ".join(missing)
                    )
                premature_v9_tables = [
                    table
                    for table in sorted(_V9_NEW_TABLES)
                    if cursor.execute(
                        "SELECT pg_catalog.to_regclass(%s) IS NOT NULL "
                        "AS present",
                        ("serverware_metadata." + table,),
                    ).fetchone()["present"]
                ]
                if premature_v9_tables:
                    raise MigrationError(
                        "schema v8 contains premature v9 tables: "
                        + ", ".join(premature_v9_tables)
                    )
                for table in sorted(existing_tables):
                    cursor.execute(
                        "LOCK TABLE serverware_metadata."
                        + '"' + table.replace('"', '""') + '"'
                        + " IN ACCESS EXCLUSIVE MODE"
                    )
                before_manifest = _schema_manifest(
                    cursor, existing_tables
                )
                before_counts, before_row_digests = _row_manifest(
                    connection, cursor, existing_tables
                )

                cursor.execute(executor_v9.authority_v9_schema_source())
                _drop_immutability_triggers(
                    cursor,
                    (
                        *_SOURCE_REVISION_TABLES,
                        "policy_authority_query_dependency_manifests",
                        "policy_authority_schema_contracts",
                        "policy_authority_owner_contracts",
                    ),
                )
                _replace_v8_constraints(cursor)
                _upgrade_writer_capability_binding(cursor)
                cursor.execute(
                    "DELETE FROM serverware_metadata."
                    "policy_authority_owner_contracts"
                )
                cursor.execute(
                    "DELETE FROM serverware_metadata."
                    "policy_authority_schema_contracts"
                )
                cursor.execute(
                    "DELETE FROM serverware_metadata."
                    "policy_authority_query_dependency_manifests"
                )
                for table in _SOURCE_REVISION_TABLES:
                    if table == "policy_authority_query_dependency_manifests":
                        continue
                    cursor.execute(
                        "UPDATE serverware_metadata."
                        + '"' + table.replace('"', '""') + '"'
                        + " SET source_revision = %s "
                        "WHERE source_revision = %s",
                        (_NEW_SOURCE_REVISION, _OLD_SOURCE_REVISION),
                    )
                _validate_replaced_constraints(cursor)
                cursor.execute(
                    "UPDATE serverware_metadata."
                    "serverware_store_migrations "
                    "SET version = 9, applied_at = "
                    "pg_catalog.clock_timestamp()::text "
                    "WHERE migration = 'policy_candidate_authority' "
                    "AND version = 8"
                )
                if cursor.rowcount != 1:
                    raise MigrationError("schema version CAS failed")

                wrapped = db.PostgresMetadataConnection(connection)
                db._install_policy_candidate_authority_guards(wrapped)
                # Install the same role/ACL closure as pristine bootstrap.
                # The complete program below is comparison input only: do not
                # replay the base DDL or silently repair unrelated v8 objects.
                db._seal_postgres_schema_acl(
                    connection,
                    schema=db._POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME,
                    runtime_role=db._METADATA_STORE_RUNTIME_ROLE,
                    table_privileges=("SELECT", "INSERT", "UPDATE", "DELETE"),
                    authority_executor_role=(
                        db._METADATA_STORE_AUTHORITY_EXECUTOR_ROLE
                    ),
                    authority_verifier_role=db._METADATA_STORE_AUTHORITY_VERIFIER_ROLE,
                    authority_verifier_read_tables=db._POLICY_AUTHORITY_VERIFIER_READ_TABLES,
                    authority_owner_role=db._METADATA_STORE_AUTHORITY_OWNER_ROLE,
                    authority_capability_issuer_role=(
                        db._METADATA_STORE_AUTHORITY_CAPABILITY_ISSUER_ROLE
                    ),
                    authority_planner_writer_role=(
                        db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE
                    ),
                    runtime_read_only_tables=(
                        db._POLICY_AUTHORITY_RUNTIME_READ_ONLY_TABLES
                    ),
                    authority_executor_function_signatures=(
                        db._POLICY_AUTHORITY_EXECUTOR_FUNCTION_SIGNATURES
                    ),
                    authority_capability_issuer_functions=(
                        db._POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTIONS
                    ),
                    authority_planner_writer_table_privileges=(
                        db._POLICY_AUTHORITY_PLANNER_WRITER_TABLE_PRIVILEGES
                    ),
                    authority_planner_writer_function_signatures=(
                        db.AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES
                    ),
                )
                structural_manifest_json, structural_manifest_digest = (
                    db._validate_policy_candidate_authority_structure(
                        wrapped,
                        require_recorded_contract=False,
                        source_schema_program=(
                            metadata_schema_source.metadata_schema_source()
                        ),
                    )
                )
                all_v9_tables = tuple(
                    sorted(
                        set(existing_tables)
                        | _V9_NEW_TABLES
                    )
                )
                after_manifest = _schema_manifest(
                    cursor, all_v9_tables
                )
                after_counts, after_row_digests = _row_manifest(
                    connection, cursor, all_v9_tables
                )
                changed_outside_allowlist = sorted(
                    table
                    for table in existing_tables
                    if table not in _ROW_MUTATION_TABLES
                    and (
                        before_counts.get(table) != after_counts.get(table)
                        or before_row_digests.get(table)
                            != after_row_digests.get(table)
                    )
                )
                count_changes = sorted(
                    table
                    for table in existing_tables
                    if table not in _COUNT_MUTATION_TABLES
                    and table not in _TERMINAL_CUSTODY_TABLES
                    and before_counts.get(table) != after_counts.get(table)
                )
                nonempty_new_tables = sorted(
                    table
                    for table in _V9_NEW_TABLES
                    if table not in _TERMINAL_CUSTODY_TABLES
                    and table not in _V9_POPULATED_CONTRACT_TABLES
                    and after_counts.get(table) != 0
                )
                empty_contract_tables = sorted(
                    table
                    for table in _V9_POPULATED_CONTRACT_TABLES
                    if after_counts.get(table, 0) == 0
                )
                if (
                    changed_outside_allowlist
                    or count_changes
                    or nonempty_new_tables
                    or empty_contract_tables
                ):
                    raise MigrationError(
                        "v8-to-v9 row mutation closure is not exact: "
                        + ", ".join(
                            changed_outside_allowlist
                            + count_changes
                            + nonempty_new_tables
                            + empty_contract_tables
                        )
                    )
                before_manifest_json = _canonical(
                    before_manifest
                ).decode("ascii")
                after_manifest_json = _canonical(
                    after_manifest
                ).decode("ascii")
                before_counts_value = {
                    "counts": before_counts,
                    "rowDigests": before_row_digests,
                }
                after_counts_value = {
                    "counts": after_counts,
                    "rowDigests": after_row_digests,
                }
                before_counts_json = _canonical(
                    before_counts_value
                ).decode("ascii")
                after_counts_json = _canonical(
                    after_counts_value
                ).decode("ascii")
                completed_at = cursor.execute(
                    "SELECT pg_catalog.clock_timestamp()::text "
                    "AS completed_at"
                ).fetchone()["completed_at"]
                receipt = {
                    "schema": authority_contract.MIGRATION_RECEIPT_SCHEMA,
                    "contractId": _CONTRACT_ID,
                    "migrationName": _MIGRATION_NAME,
                    "sourceVersion": 8,
                    "targetVersion": 9,
                    "migrationSha256": migration_sha256,
                    "sourceRevision": _NEW_SOURCE_REVISION,
                    "operationContractDigest":
                        authority_contract.OPERATION_MANIFEST_DIGEST,
                    "signerIdentityDigest": signer_identity_digest,
                    "beforeManifestDigest": _digest(
                        authority_contract.MIGRATION_MANIFEST_DIGEST_DOMAIN,
                        before_manifest_json.encode("ascii"),
                    ),
                    "beforeRowCountsDigest": _digest(
                        authority_contract.MIGRATION_ROWS_DIGEST_DOMAIN,
                        before_counts_json.encode("ascii"),
                    ),
                    "afterManifestDigest": _digest(
                        authority_contract.MIGRATION_MANIFEST_DIGEST_DOMAIN,
                        after_manifest_json.encode("ascii"),
                    ),
                    "afterRowCountsDigest": _digest(
                        authority_contract.MIGRATION_ROWS_DIGEST_DOMAIN,
                        after_counts_json.encode("ascii"),
                    ),
                    "terminal": True,
                    "completedAt": str(completed_at),
                    "status": "completed",
                }
                receipt_json = _canonical(receipt).decode("ascii")
                receipt_digest = _digest(
                    authority_contract.MIGRATION_RECEIPT_DIGEST_DOMAIN,
                    receipt_json.encode("ascii"),
                )
                signature_message = _digest(
                    authority_contract.MIGRATION_RECEIPT_SIGNATURE_DOMAIN,
                    receipt_json.encode("ascii"),
                ).encode("ascii")
                (
                    signature_algorithm,
                    detached_signature,
                    detached_signature_digest,
                ) = _signature_material(
                    signature_message,
                    signature_file=signature_file,
                    signer_socket=signer_socket,
                    public_key_bytes=signer_public_key,
                )
                recorded_receipt = (
                    record_policy_candidate_authority_v8_to_v9_receipt(
                        migration_sha256=migration_sha256,
                        before_manifest_json=before_manifest_json,
                        before_row_counts_json=before_counts_json,
                        after_manifest_json=after_manifest_json,
                        after_row_counts_json=after_counts_json,
                        signer_public_key_base64url=(
                            signer_public_key_base64url
                        ),
                        detached_signature=detached_signature,
                        completed_at=str(completed_at),
                        connection=wrapped,
                    )
                )
                if (
                    not isinstance(recorded_receipt, Mapping)
                    or recorded_receipt.get("receipt") != receipt
                    or recorded_receipt.get("receiptDigest")
                    != receipt_digest
                    or recorded_receipt.get("status") != "completed"
                    or recorded_receipt.get("exactReplay") is not False
                ):
                    raise MigrationError(
                        "v9 migration store did not persist the exact receipt"
                    )
                cursor.execute(
                    "INSERT INTO serverware_metadata."
                    "policy_authority_schema_contracts ("
                    "schema_version, contract_id, source_revision, "
                    "source_contract_digest, structural_manifest_json, "
                    "structural_manifest_digest, "
                    "offline_migration_receipt_digest, installed_at"
                    ") VALUES (9, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        "serverware.policyCandidateAuthoritySchema/v9",
                        _NEW_SOURCE_REVISION,
                        db._policy_candidate_authority_source_contract_digest(),
                        structural_manifest_json,
                        structural_manifest_digest,
                        receipt_digest,
                        str(completed_at),
                    ),
                )
                owner_contract = (
                    db._validate_policy_authority_owner_apply_function(
                        cursor,
                        source_structural_manifest_digest=(
                            structural_manifest_digest
                        ),
                    )
                )
                cursor.execute(
                    "INSERT INTO serverware_metadata."
                    "policy_authority_owner_contracts ("
                    "contract_id, schema_version, source_revision, "
                    "function_name, function_definition_digest, "
                    "verifier_spki_digest, verifier_measurement_digest, "
                    "verification_profile_digest, response_max_bytes, "
                    "response_max_age_ns, max_clock_skew_ns, recorded_at"
                    ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, "
                    "%s, %s, %s, %s)",
                    (
                        owner_contract["contract_id"],
                        owner_contract["schema_version"],
                        owner_contract["source_revision"],
                        owner_contract["function_name"],
                        owner_contract["function_definition_digest"],
                        owner_contract["verifier_spki_digest"],
                        owner_contract["verifier_measurement_digest"],
                        owner_contract["verification_profile_digest"],
                        owner_contract["response_max_bytes"],
                        owner_contract["response_max_age_ns"],
                        owner_contract["max_clock_skew_ns"],
                        str(completed_at),
                    ),
                )
                final_version = cursor.execute(
                    "SELECT version FROM serverware_metadata."
                    "serverware_store_migrations "
                    "WHERE migration = 'policy_candidate_authority'"
                ).fetchone()
                if final_version is None or int(final_version["version"]) != 9:
                    raise MigrationError("schema v9 terminal version is absent")
                db._validate_policy_candidate_authority_structure(
                    wrapped,
                    require_recorded_contract=True,
                    source_schema_program=(
                        metadata_schema_source.metadata_schema_source()
                    ),
                )
                return _terminal_response(
                    receipt=receipt,
                    receipt_digest=receipt_digest,
                    signer_identity_digest=signer_identity_digest,
                    signer_public_key_base64url=(
                        signer_public_key_base64url
                    ),
                    signature_algorithm=signature_algorithm,
                    detached_signature=detached_signature,
                    detached_signature_digest=(
                        detached_signature_digest
                    ),
                )
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline, atomic Serverware authority v8-to-v9 migration"
    )
    parser.add_argument(
        "--dsn-fd",
        type=int,
        required=True,
        help="descriptor containing the PostgreSQL bootstrap DSN",
    )
    parser.add_argument(
        "--migration-sha256",
        required=True,
        help="externally measured sha256 digest of this migration source",
    )
    parser.add_argument(
        "--detached-signature",
        type=Path,
        help=(
            "base64url Ed25519 signature over the domain-separated "
            "migration receipt signature message"
        ),
    )
    parser.add_argument(
        "--signer-socket",
        type=Path,
        help=(
            "external signer UDS; receives the framed domain-separated "
            "receipt signature message and returns a framed base64url "
            "Ed25519 signature"
        ),
    )
    parser.add_argument(
        "--signer-public-key",
        type=Path,
        required=True,
        help="raw 32-byte Ed25519 public key",
    )
    parser.add_argument(
        "--expected-signer-identity-digest",
        required=True,
        help=(
            "externally pinned domain-separated migration signer identity "
            "digest"
        ),
    )
    arguments = parser.parse_args()
    result = migrate(
        dsn_descriptor=arguments.dsn_fd,
        migration_sha256=arguments.migration_sha256,
        signature_file=arguments.detached_signature,
        signer_socket=arguments.signer_socket,
        public_key_file=arguments.signer_public_key,
        expected_signer_digest=(
            arguments.expected_signer_identity_digest
        ),
    )
    print(_canonical(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
