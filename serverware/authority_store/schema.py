from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping, MutableMapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_contract
from serverware.authority_store import counted_installation
from serverware.authority_store import metadata_schema_source
from serverware.authority_store import postgres_trigger_manifest
from serverware.authority_store.verifier_read_sql import VERIFIER_READ_PRIVILEGE_SQL_DIGEST
from serverware.authority_store.completed_v9_schema_source import (
    COMPLETED_V9_RECEIPT_TABLE as _COMPLETED_V9_RECEIPT_TABLE,
    completed_v9_schema_programs,
    require_metadata_schema_program,
)
from serverware.authority_store.wire_json_sql import WIRE_JSON_FUNCTION_NAMES
from serverware.authority_store.audit_capacity_sql import (
    AUDIT_CAPACITY_FUNCTION_NAME,
    AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES,
)

_EXTRACTED_NAMES = frozenset(
    {
        "_policy_candidate_authority_migration_version",
        "_policy_candidate_authority_framed_digest",
        "_policy_candidate_authority_source_contract_digest",
        "_policy_candidate_authority_identifier",
        "_policy_candidate_authority_object_name",
        "_policy_candidate_authority_table_reference",
        "_policy_candidate_authority_index_reference",
        "_policy_candidate_authority_normalize_sql",
        "_policy_candidate_authority_object_definition",
        "_policy_candidate_authority_canonicalize_namespace",
        "_policy_candidate_authority_table_manifest",
        "_policy_candidate_authority_schema_tables",
        "_policy_candidate_authority_postgres_object_authority",
        "_policy_candidate_authority_structure_manifest",
        "_policy_candidate_authority_manifest_digest",
        "_policy_candidate_authority_required_guard_names",
        "_policy_candidate_authority_expected_structure_manifest",
        "_validate_policy_candidate_authority_structure",
        "_policy_candidate_authority_offline_required",
        "_policy_candidate_authority_table_has_rows",
        "_policy_candidate_authority_offline_receipt",
        "record_policy_candidate_authority_v8_to_v9_receipt",
        "repair_policy_candidate_authority_completed_v9_receipt",
        "_EXTRACTED_NAMES",
        "bind_db_globals",
    }
)
_FACADE_EXPORTS = (
    "record_policy_candidate_authority_v8_to_v9_receipt",
    "repair_policy_candidate_authority_completed_v9_receipt",
)


def bind_db_globals(namespace: Mapping[str, Any]) -> None:
    for name, value in namespace.items():
        if not name.startswith("__") and name not in _EXTRACTED_NAMES:
            globals()[name] = value
    if isinstance(namespace, MutableMapping):
        for name in _FACADE_EXPORTS:
            namespace[name] = globals()[name]


def _policy_candidate_authority_migration_version(conn: Any) -> int:
    row = conn.execute(
        "SELECT version FROM serverware_store_migrations WHERE migration = ?",
        (_POLICY_CANDIDATE_AUTHORITY_MIGRATION,),
    ).fetchone()
    return int(row["version"]) if row is not None else 0


def _policy_candidate_authority_framed_digest(
    domain: str, *frames: bytes
) -> str:
    hasher = hashlib.sha256()
    encoded_domain = domain.encode("ascii")
    hasher.update(len(encoded_domain).to_bytes(8, "big"))
    hasher.update(encoded_domain)
    for frame in frames:
        hasher.update(len(frame).to_bytes(8, "big"))
        hasher.update(frame)
    return "sha256:" + hasher.hexdigest()


def _policy_candidate_authority_decode_base64url(
    value: object,
    *,
    label: str,
    size: int,
) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or "=" in value
        or any(
            character not in
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in value
        )
    ):
        raise PolicyCandidateAuthorityError(
            f"{label} is not canonical base64url"
        )
    try:
        payload = base64.urlsafe_b64decode(
            value + "=" * ((4 - len(value) % 4) % 4)
        )
    except (ValueError, TypeError) as exc:
        raise PolicyCandidateAuthorityError(
            f"{label} is not canonical base64url"
        ) from exc
    if (
        len(payload) != size
        or base64.urlsafe_b64encode(payload)
            .rstrip(b"=")
            .decode("ascii")
            != value
    ):
        raise PolicyCandidateAuthorityError(
            f"{label} is not exact"
        )
    return payload


def _policy_candidate_authority_source_contract_digest() -> str:
    issuer_functions = set(_POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTIONS)
    if (
        set(authority_contract.CAPABILITY_ISSUER_FUNCTION_SIGNATURES)
        != issuer_functions
        or set(authority_contract.CAPABILITY_ISSUER_FUNCTION_ARGUMENTS)
        != issuer_functions
        or any(
            len(
                authority_contract
                .CAPABILITY_ISSUER_FUNCTION_SIGNATURES[function_name]
            )
            != len(
                authority_contract
                .CAPABILITY_ISSUER_FUNCTION_ARGUMENTS[function_name]
            )
            for function_name in issuer_functions
        )
    ):
        raise PolicyCandidateAuthorityError(
            "authority capability-issuer producer contract is incomplete"
        )
    material = dumps(
        {
            "contract": _POLICY_CANDIDATE_AUTHORITY_SCHEMA_CONTRACT,
            "schemaVersion": _POLICY_CANDIDATE_AUTHORITY_SCHEMA_VERSION,
            "sourceRevision": _POLICY_CANDIDATE_AUTHORITY_SOURCE_REVISION,
            "immutableTables": list(
                _POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES
            ),
            "headTables": list(_POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES),
            "jitAuthorityRuntimeReadOnlyTables":
                sorted(_JIT_AUTHORITY_RUNTIME_READ_ONLY_TABLES),
            "authorityRuntimeReadOnlyTables":
                sorted(_POLICY_AUTHORITY_RUNTIME_READ_ONLY_TABLES),
            "v9AdditionalProtectedTables":
                list(authority_contract.V9_ADDITIONAL_PROTECTED_TABLES),
            "postgresCountedStoreColumns": {
                table: list(columns)
                for table, columns in authority_contract.POSTGRES_COUNTED_STORE_COLUMNS.items()
            },
            "postgresCountedFunctionContracts": {
                name: {
                    field: list(value) if isinstance(value, tuple) else value
                    for field, value in contract.items()
                }
                for name, contract in authority_contract.POSTGRES_COUNTED_FUNCTION_CONTRACTS.items()
            },
            "postgresCountedMaintenance":
                dict(authority_contract.POSTGRES_COUNTED_MAINTENANCE_CONTRACT),
            "postgresCountedInstallation":
                counted_installation.counted_installation_contract(),
            "objectOwnershipContract":
                "serverware.policyAuthorityObjectOwnership/v1",
            "authorityOwnerRole": _METADATA_STORE_AUTHORITY_OWNER_ROLE,
            "verifierReadContract": authority_contract.VERIFIER_READ_CONTRACT,
            "verifierReadRole": _METADATA_STORE_AUTHORITY_VERIFIER_ROLE,
            "verifierReadTables": sorted(authority_contract.VERIFIER_READ_TABLES),
            "verifierReadPrivilegeSqlDigest": VERIFIER_READ_PRIVILEGE_SQL_DIGEST,
            "metadataSchemaProgramDigest":
                _policy_candidate_authority_framed_digest(
                    "serverware.metadataSchemaProgram/v1",
                    metadata_schema_source.metadata_schema_source().encode("utf-8"),
                ),
            "measuredAuthorityServiceSource":
                "serverware/authority_service.py",
            "authorityServiceSourcePresent": True,
            "externalJitReleaseAuthorityWriterDeploymentRequired": False,
            "externalExportAuthorizationWriterDeploymentRequired": False,
            "hotRuntimeMayMutateJitReleaseAuthority": False,
            "inProcessAuthorityMutationDispatch":
                "measured-three-role-one-use-controlled-writer-v1",
            "runtimeRoles": list(_POLICY_AUTHORITY_RUNTIME_ROLES),
            "semanticOutcomes": list(_POLICY_AUTHORITY_OUTCOMES),
            "responseClasses": list(_POLICY_AUTHORITY_RESPONSE_CLASSES),
            "latencySeries": list(_POLICY_AUTHORITY_LATENCY_SERIES),
            "latencyBuckets": [
                [lower, upper]
                for lower, upper in _POLICY_AUTHORITY_LATENCY_BUCKETS
            ],
            "offlineMigrationContract": (
                _POLICY_CANDIDATE_AUTHORITY_OFFLINE_MIGRATION_CONTRACT_ID
            ),
            "ownerApplyFunction": _POLICY_AUTHORITY_OWNER_APPLY_FUNCTION,
            "ownerVerifierResponseMaxBytes": (
                _POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_BYTES
            ),
            "ownerVerifierResponseMaxAgeNs": (
                _POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_AGE_NS
            ),
            "ownerVerifierMaxClockSkewNs": (
                _POLICY_AUTHORITY_VERIFIER_MAX_CLOCK_SKEW_NS
            ),
            "ownerMaxWrites": _POLICY_AUTHORITY_OWNER_MAX_WRITES,
            "ownerMaxQueryProofs":
                _POLICY_AUTHORITY_OWNER_MAX_QUERY_PROOFS,
            "ownerMaxQuerySelectors":
                _POLICY_AUTHORITY_OWNER_MAX_QUERY_SELECTORS,
            "operationContractSchema":
                authority_contract.CONTRACT_SCHEMA,
            "operationContractDigest":
                authority_contract.OPERATION_MANIFEST_DIGEST,
            "ownerOperationQueryManifest": {
                operation: [dict(entry) for entry in entries]
                for operation, entries in (
                    _POLICY_AUTHORITY_OPERATION_QUERY_MANIFEST.items()
                )
            },
            "authenticatedTreeDepth":
                _POLICY_AUTHORITY_AUTHENTICATED_TREE_DEPTH,
            "authenticatedTreeRadix":
                _POLICY_AUTHORITY_AUTHENTICATED_TREE_RADIX,
            "ownerOperationWriteDependencies": {
                operation: list(tables)
                for operation, tables in (
                    _POLICY_AUTHORITY_OPERATION_WRITE_TABLES.items()
                )
            },
            "ownerOperationDependencyClasses": {
                operation: {
                    "businessReads": list(spec["businessReads"]),
                    "businessWrites": list(spec["businessWrites"]),
                    "authorizationReads":
                        list(spec["authorizationReads"]),
                    "frameworkPreconditions":
                        list(spec["frameworkPreconditions"]),
                    "frameworkWrites":
                        list(spec["frameworkWrites"]),
                }
                for operation, spec in sorted(
                    authority_contract.OPERATIONS.items()
                )
            },
            "sqlGrantManifest": {
                operation: {
                    field: (
                        list(value)
                        if isinstance(value, tuple)
                        else value
                    )
                    for field, value in grant.items()
                }
                for operation, grant in sorted(
                    authority_contract.SQL_GRANT_MANIFEST.items()
                )
            },
            "frameworkCustodyExcludedFromBusinessRoots": True,
            "ownerLockTimeout": _POLICY_AUTHORITY_OWNER_LOCK_TIMEOUT,
            "ownerStatementTimeout":
                _POLICY_AUTHORITY_OWNER_STATEMENT_TIMEOUT,
            "ownerPostgresMajor":
                _POLICY_AUTHORITY_OWNER_POSTGRES_MAJOR,
            "authorityExecutorFunctions":
                sorted(_POLICY_AUTHORITY_EXECUTOR_FUNCTIONS),
            "authorityPlannerWriterFunctionSignatures": {
                name: list(argument_types)
                for name, argument_types
                in AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES
            },
            "authorityCapabilityIssuerRole":
                _METADATA_STORE_AUTHORITY_CAPABILITY_ISSUER_ROLE,
            "authorityCapabilityIssuerFunctions":
                sorted(_POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTIONS),
            "authorityCapabilityIssuerFunctionSignatures": {
                function_name: list(argument_types)
                for function_name, argument_types in sorted(
                    authority_contract
                    .CAPABILITY_ISSUER_FUNCTION_SIGNATURES.items()
                )
            },
            "authorityCapabilityIssuerFunctionArguments": {
                function_name: list(argument_names)
                for function_name, argument_names in sorted(
                    authority_contract
                    .CAPABILITY_ISSUER_FUNCTION_ARGUMENTS.items()
                )
            },
            "offlineMigrationReceiptProducers": {
                contract_id: {
                    "handler": spec["handler"],
                    "arguments": list(spec["arguments"]),
                }
                for contract_id, spec in sorted(
                    authority_contract
                    .OFFLINE_MIGRATION_RECEIPT_PRODUCERS.items()
                )
            },
            "frozenMetadataMaxJsonBytes":
                _POLICY_AUTHORITY_FROZEN_METADATA_MAX_JSON_BYTES,
            "frozenRowsMaxJsonBytes":
                _POLICY_AUTHORITY_FROZEN_ROWS_MAX_JSON_BYTES,
            "pageMaxJsonBytes":
                _POLICY_AUTHORITY_PAGE_MAX_JSON_BYTES,
            "verifierProcessMode":
                _POLICY_AUTHORITY_VERIFIER_PROCESS_MODE,
            "verifierSignatureDomain":
                _POLICY_AUTHORITY_VERIFIER_SIGNATURE_DOMAIN,
            "databaseVerificationMode":
                _POLICY_AUTHORITY_DATABASE_VERIFICATION_MODE,
            "externalVerifierSourceRequired": False,
            "postgresVerifiesEd25519": False,
        }
    ).encode("utf-8")
    return _policy_candidate_authority_framed_digest(
        "serverware.policyCandidateAuthoritySourceContract/v1",
        material,
    )


def _policy_candidate_authority_identifier(value: str) -> str:
    if re.fullmatch(r"[a-z][a-z0-9_]{0,127}", value) is None:
        raise PolicyCandidateAuthorityError(
            "candidate-authority schema identifier is invalid"
        )
    return '"' + value + '"'


def _policy_candidate_authority_object_name(*parts: str) -> str:
    """Return one source-deterministic identifier accepted by PostgreSQL."""
    raw = "_".join(parts)
    if re.fullmatch(r"[a-z][a-z0-9_]*", raw) is None:
        raise PolicyCandidateAuthorityError(
            "candidate-authority object-name source is invalid"
        )
    if len(raw.encode("ascii")) <= 63:
        return raw
    suffix = hashlib.sha256(raw.encode("ascii")).hexdigest()[:12]
    prefix = raw.encode("ascii")[:50].decode("ascii").rstrip("_")
    name = f"{prefix}_{suffix}"
    if len(name.encode("ascii")) > 63:
        raise PolicyCandidateAuthorityError(
            "candidate-authority object-name derivation overflowed"
        )
    return name


def _policy_candidate_authority_table_reference(
    conn: Any, table: str
) -> str:
    table_identifier = _policy_candidate_authority_identifier(table)
    if not isinstance(conn, PostgresMetadataConnection):
        return table_identifier
    schema_identifier = _policy_candidate_authority_identifier(
        _POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME
    )
    return f"{schema_identifier}.{table_identifier}"


def _policy_candidate_authority_index_reference(
    conn: Any, index: str
) -> str:
    return _policy_candidate_authority_table_reference(conn, index)


def _policy_candidate_authority_normalize_sql(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).strip().split())


def _policy_candidate_authority_object_definition(
    *, name: str, definition: Any
) -> dict[str, str]:
    normalized = _policy_candidate_authority_normalize_sql(definition)
    return {
        "name": name,
        "definition": normalized,
        "definitionDigest": _policy_candidate_authority_framed_digest(
            "serverware.policyCandidateAuthoritySchemaObject/v1",
            name.encode("utf-8"),
            normalized.encode("utf-8"),
        ),
    }


def _policy_candidate_authority_canonicalize_namespace(
    definition: Any,
    *,
    actual_namespace: str,
    canonical_namespace: str,
) -> str:
    normalized = _policy_candidate_authority_normalize_sql(definition)
    if actual_namespace == canonical_namespace:
        return normalized
    return normalized.replace(
        f'"{actual_namespace}".',
        f'"{canonical_namespace}".',
    ).replace(
        actual_namespace + ".",
        canonical_namespace + ".",
    )


def _policy_candidate_authority_table_manifest(
    conn: Any,
    table: str,
    *,
    canonical_namespace: str | None = None,
) -> dict[str, Any]:
    quoted_table = _policy_candidate_authority_identifier(table)
    if not _metadata_table_exists(conn, table):
        return {"name": table, "present": False}
    if isinstance(conn, PostgresMetadataConnection):
        namespace_row = conn.execute(
            "SELECT pg_catalog.current_schema() AS current_schema"
        ).fetchone()
        if namespace_row is None:
            raise PolicyCandidateAuthorityError(
                "candidate-authority PostgreSQL namespace is unavailable"
            )
        actual_namespace = str(namespace_row["current_schema"])
        canonical_namespace = canonical_namespace or actual_namespace
        relation_authority = conn.execute(
            "SELECT owner.rolname AS owner_name, "
            "relation.relacl IS NULL AS acl_is_default "
            "FROM pg_catalog.pg_class AS relation "
            "JOIN pg_catalog.pg_namespace AS namespace "
            "ON namespace.oid = relation.relnamespace "
            "JOIN pg_catalog.pg_roles AS owner "
            "ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = ? AND relation.relname = ? "
            "AND relation.relkind IN ('r', 'p')",
            (actual_namespace, table),
        ).fetchone()
        relation_acl_rows = conn.execute(
            "SELECT CASE "
            "WHEN grant_entry.grantee = 0 THEN 'PUBLIC' "
            "WHEN grant_entry.grantee = relation.relowner "
            "THEN 'schema-owner' "
            "WHEN grantee.rolname = ? THEN 'runtime' "
            "ELSE grantee.rolname END AS grantee, "
            "grant_entry.privilege_type, grant_entry.is_grantable "
            "FROM pg_catalog.pg_class AS relation "
            "JOIN pg_catalog.pg_namespace AS namespace "
            "ON namespace.oid = relation.relnamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE("
            "relation.relacl, pg_catalog.acldefault("
            "'r', relation.relowner))) AS grant_entry "
            "LEFT JOIN pg_catalog.pg_roles AS grantee "
            "ON grantee.oid = grant_entry.grantee "
            "WHERE namespace.nspname = ? AND relation.relname = ? "
            "ORDER BY grantee, grant_entry.privilege_type",
            (_METADATA_STORE_RUNTIME_ROLE, actual_namespace, table),
        ).fetchall()
        if relation_authority is None:
            raise PolicyCandidateAuthorityError(
                "candidate-authority table owner is unavailable"
            )
        table_authority = {
            "owner": "schema-owner",
            "aclIsDefault": bool(relation_authority["acl_is_default"]),
            "acl": [
                {
                    "grantee": str(row["grantee"]),
                    "privilege": str(row["privilege_type"]),
                    "grantable": bool(row["is_grantable"]),
                }
                for row in relation_acl_rows
            ],
        }

        def canonical_definition(value: Any) -> str:
            return _policy_candidate_authority_canonicalize_namespace(
                value,
                actual_namespace=actual_namespace,
                canonical_namespace=canonical_namespace,
            )

        columns = [
            {
                "name": str(row["column_name"]),
                "type": str(row["data_type"]),
                "udt": str(row["udt_name"]),
                "nullable": str(row["is_nullable"]) == "YES",
                "default": _policy_candidate_authority_normalize_sql(
                    row["column_default"]
                ),
                "ordinal": int(row["ordinal_position"]),
            }
            for row in conn.execute(
                "SELECT column_name, data_type, udt_name, is_nullable, "
                "column_default, ordinal_position "
                "FROM information_schema.columns "
                "WHERE table_schema = pg_catalog.current_schema() "
                "AND table_name = ? "
                "ORDER BY ordinal_position",
                (table,),
            ).fetchall()
        ]
        constraint_rows = conn.execute(
            """
            SELECT
                constraint_record.conname AS constraint_name,
                constraint_record.contype AS constraint_type,
                pg_catalog.pg_get_constraintdef(
                    constraint_record.oid, true
                )
                    AS definition,
                COALESCE(
                    ARRAY(
                        SELECT attribute.attname
                        FROM pg_catalog.unnest(constraint_record.conkey)
                            WITH ORDINALITY AS key_column(attnum, ordinal)
                        JOIN pg_catalog.pg_attribute AS attribute
                          ON attribute.attrelid =
                                constraint_record.conrelid
                         AND attribute.attnum = key_column.attnum
                        ORDER BY key_column.ordinal
                    ),
                    ARRAY[]::text[]
                ) AS local_columns,
                foreign_relation.relname AS foreign_table,
                COALESCE(
                    ARRAY(
                        SELECT attribute.attname
                        FROM pg_catalog.unnest(constraint_record.confkey)
                            WITH ORDINALITY AS key_column(attnum, ordinal)
                        JOIN pg_catalog.pg_attribute AS attribute
                          ON attribute.attrelid =
                                constraint_record.confrelid
                         AND attribute.attnum = key_column.attnum
                        ORDER BY key_column.ordinal
                    ),
                    ARRAY[]::text[]
                ) AS foreign_columns
            FROM pg_catalog.pg_constraint AS constraint_record
            JOIN pg_catalog.pg_class AS relation
              ON relation.oid = constraint_record.conrelid
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            LEFT JOIN pg_catalog.pg_class AS foreign_relation
              ON foreign_relation.oid = constraint_record.confrelid
            WHERE namespace.nspname = pg_catalog.current_schema()
              AND relation.relname = ?
            ORDER BY constraint_record.contype, constraint_record.conname
            """,
            (table,),
        ).fetchall()
        constraints = [
            {
                "name": str(row["constraint_name"]),
                "type": str(row["constraint_type"]),
                "columns": [str(value) for value in row["local_columns"]],
                "foreignTable": (
                    str(row["foreign_table"])
                    if row["foreign_table"] is not None
                    else None
                ),
                "foreignColumns": [
                    str(value) for value in row["foreign_columns"]
                ],
                **_policy_candidate_authority_object_definition(
                    name=str(row["constraint_name"]),
                    definition=canonical_definition(row["definition"]),
                ),
            }
            for row in constraint_rows
        ]
        index_rows = conn.execute(
            """
            SELECT
                index_relation.relname AS index_name,
                index_record.indisunique AS is_unique,
                index_record.indisprimary AS is_primary,
                pg_catalog.pg_get_indexdef(index_relation.oid) AS definition,
                index_owner.rolname AS owner_name,
                index_relation.relacl IS NULL AS acl_is_empty,
                ARRAY(
                    SELECT pg_catalog.pg_get_indexdef(
                        index_relation.oid, position, true
                    )
                    FROM pg_catalog.generate_series(
                        1, index_record.indnkeyatts
                    ) AS position
                    ORDER BY position
                ) AS index_columns
            FROM pg_catalog.pg_index AS index_record
            JOIN pg_catalog.pg_class AS relation
              ON relation.oid = index_record.indrelid
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            JOIN pg_catalog.pg_class AS index_relation
              ON index_relation.oid = index_record.indexrelid
            JOIN pg_catalog.pg_roles AS index_owner
              ON index_owner.oid = index_relation.relowner
            WHERE namespace.nspname = pg_catalog.current_schema()
              AND relation.relname = ?
              AND index_record.indisvalid
              AND index_record.indisready
            ORDER BY index_relation.relname
            """,
            (table,),
        ).fetchall()
        indexes = [
            {
                "name": str(row["index_name"]),
                "unique": bool(row["is_unique"]),
                "primary": bool(row["is_primary"]),
                "columns": [str(value) for value in row["index_columns"]],
                "authority": {
                    "owner": "schema-owner",
                    "acl": [],
                    "aclIsEmpty": bool(row["acl_is_empty"]),
                },
                **_policy_candidate_authority_object_definition(
                    name=str(row["index_name"]),
                    definition=canonical_definition(row["definition"]),
                ),
            }
            for row in index_rows
        ]
        try:
            triggers = postgres_trigger_manifest.table_trigger_manifest(
                conn.raw_connection,
                namespace=actual_namespace,
                table=table,
                canonical_definition=canonical_definition,
                object_definition=_policy_candidate_authority_object_definition,
            )
        except ValueError as exc:
            raise PolicyCandidateAuthorityError(str(exc)) from exc
        table_definition = ""
    else:
        table_authority = None
        column_rows = conn.execute(
            f"PRAGMA table_xinfo({quoted_table})"
        ).fetchall()
        columns = [
            {
                "name": str(row["name"]),
                "type": str(row["type"] or "").upper(),
                "nullable": not bool(row["notnull"]),
                "default": _policy_candidate_authority_normalize_sql(
                    row["dflt_value"]
                ),
                "ordinal": int(row["cid"]) + 1,
                "primaryKeyOrdinal": int(row["pk"]),
                "hidden": int(row["hidden"]),
            }
            for row in column_rows
        ]
        foreign_rows = conn.execute(
            f"PRAGMA foreign_key_list({quoted_table})"
        ).fetchall()
        foreign_groups: dict[int, list[Any]] = {}
        for row in foreign_rows:
            foreign_groups.setdefault(int(row["id"]), []).append(row)
        constraints = []
        for foreign_id, rows in sorted(foreign_groups.items()):
            ordered = sorted(rows, key=lambda item: int(item["seq"]))
            constraints.append(
                {
                    "name": f"sqlite_fk_{table}_{foreign_id}",
                    "type": "f",
                    "columns": [str(row["from"]) for row in ordered],
                    "foreignTable": str(ordered[0]["table"]),
                    "foreignColumns": [str(row["to"]) for row in ordered],
                    "onUpdate": str(ordered[0]["on_update"]),
                    "onDelete": str(ordered[0]["on_delete"]),
                    "match": str(ordered[0]["match"]),
                    **_policy_candidate_authority_object_definition(
                        name=f"sqlite_fk_{table}_{foreign_id}",
                        definition=dumps(
                            {
                                "columns": [
                                    str(row["from"]) for row in ordered
                                ],
                                "foreignColumns": [
                                    str(row["to"]) for row in ordered
                                ],
                                "foreignTable": str(ordered[0]["table"]),
                                "match": str(ordered[0]["match"]),
                                "onDelete": str(ordered[0]["on_delete"]),
                                "onUpdate": str(ordered[0]["on_update"]),
                            }
                        ),
                    ),
                }
            )
        indexes = []
        for index_row in conn.execute(
            f"PRAGMA index_list({quoted_table})"
        ).fetchall():
            index_name = str(index_row["name"])
            quoted_index = _policy_candidate_authority_identifier(index_name)
            index_columns = [
                str(row["name"])
                for row in conn.execute(
                    f"PRAGMA index_xinfo({quoted_index})"
                ).fetchall()
                if int(row["key"]) == 1 and row["name"] is not None
            ]
            definition_row = conn.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type = 'index' AND name = ?",
                (index_name,),
            ).fetchone()
            indexes.append(
                {
                    "name": index_name,
                    "unique": bool(index_row["unique"]),
                    "primary": str(index_row["origin"]) == "pk",
                    "origin": str(index_row["origin"]),
                    "partial": bool(index_row["partial"]),
                    "columns": index_columns,
                    **_policy_candidate_authority_object_definition(
                        name=index_name,
                        definition=(
                            definition_row["sql"]
                            if definition_row is not None
                            else dumps(
                                {
                                    "columns": index_columns,
                                    "origin": str(index_row["origin"]),
                                    "unique": bool(index_row["unique"]),
                                }
                            )
                        ),
                    ),
                }
            )
        trigger_rows = conn.execute(
            "SELECT name, sql FROM sqlite_master "
            "WHERE type = 'trigger' AND tbl_name = ? ORDER BY name",
            (table,),
        ).fetchall()
        triggers = [
            _policy_candidate_authority_object_definition(
                name=str(row["name"]), definition=row["sql"]
            )
            for row in trigger_rows
        ]
        table_row = conn.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        table_definition = _policy_candidate_authority_normalize_sql(
            table_row["sql"] if table_row is not None else ""
        )
    primary_key = [
        str(column["name"])
        for column in sorted(
            columns,
            key=lambda item: int(item.get("primaryKeyOrdinal", 0)),
        )
        if int(column.get("primaryKeyOrdinal", 0)) > 0
    ]
    if isinstance(conn, PostgresMetadataConnection):
        primary_constraints = [
            constraint
            for constraint in constraints
            if constraint["type"] == "p"
        ]
        if len(primary_constraints) != 1:
            raise PolicyCandidateAuthorityError(
                f"candidate-authority table {table} has no exact primary key"
            )
        primary_key = list(primary_constraints[0]["columns"])
    return {
        "name": table,
        "present": True,
        "columns": columns,
        "primaryKey": primary_key,
        "constraints": constraints,
        "indexes": sorted(indexes, key=lambda item: item["name"]),
        "triggers": triggers,
        "tableDefinition": table_definition,
        "tableDefinitionDigest": (
            _policy_candidate_authority_framed_digest(
                "serverware.policyCandidateAuthorityTableDefinition/v1",
                table.encode("utf-8"),
                table_definition.encode("utf-8"),
            )
        ),
        "authority": table_authority,
    }


def _policy_candidate_authority_schema_tables(*, postgres: bool = False) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            _POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES
            + _POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES
            + authority_contract.V9_ADDITIONAL_PROTECTED_TABLES
            + (authority_contract.POSTGRES_COUNTED_STORE_TABLES if postgres else ())
            + (
                "metadata_audit_outbox",
                "rbac_authority_state",
                "rbac_role_bindings",
            )
        )
    )


def _policy_candidate_authority_postgres_object_authority(
    conn: Any,
    *,
    namespace: str,
) -> dict[str, Any]:
    namespace_row = conn.execute(
        "SELECT namespace.nspowner AS owner_oid, "
        "owner_role.rolname AS owner_role, "
        "owner_role.rolcanlogin, owner_role.rolsuper, "
        "owner_role.rolcreaterole, owner_role.rolcreatedb, "
        "owner_role.rolreplication, owner_role.rolbypassrls, "
        "namespace.nspacl IS NULL AS acl_is_default "
        "FROM pg_catalog.pg_namespace AS namespace "
        "JOIN pg_catalog.pg_roles AS owner_role "
        "ON owner_role.oid = namespace.nspowner "
        "WHERE namespace.nspname = ?",
        (namespace,),
    ).fetchone()
    if (
        namespace_row is None
        or type(_METADATA_STORE_AUTHORITY_OWNER_ROLE) is not str
        or not _METADATA_STORE_AUTHORITY_OWNER_ROLE
        or type(namespace_row.get("owner_role")) is not str
        or namespace_row["owner_role"] != _METADATA_STORE_AUTHORITY_OWNER_ROLE
        or type(namespace_row.get("owner_oid")) is not int
        or not 0 < namespace_row["owner_oid"] <= 2**32 - 1
        or any(
            namespace_row.get(field) is not False
            for field in (
                "rolcanlogin", "rolsuper", "rolcreaterole", "rolcreatedb",
                "rolreplication", "rolbypassrls",
            )
        )
    ):
        raise PolicyCandidateAuthorityError(
            "metadata namespace authority owner is not source exact"
        )
    owner_oid = namespace_row["owner_oid"]

    def normalized_acl(rows: list[Any]) -> list[dict[str, Any]]:
        return [
            {
                "grantee": str(row["grantee"]),
                "privilege": str(row["privilege_type"]),
                "grantable": bool(row["is_grantable"]),
            }
            for row in rows
        ]

    namespace_acl = normalized_acl(
        conn.execute(
            "SELECT CASE "
            "WHEN grant_entry.grantee = 0 THEN 'PUBLIC' "
            "WHEN grant_entry.grantee = namespace.nspowner "
            "THEN 'schema-owner' "
            "WHEN grantee.rolname = ? THEN 'runtime' "
            "ELSE grantee.rolname END AS grantee, "
            "grant_entry.privilege_type, grant_entry.is_grantable "
            "FROM pg_catalog.pg_namespace AS namespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE("
            "namespace.nspacl, pg_catalog.acldefault("
            "'n', namespace.nspowner))) AS grant_entry "
            "LEFT JOIN pg_catalog.pg_roles AS grantee "
            "ON grantee.oid = grant_entry.grantee "
            "WHERE namespace.nspname = ? "
            "ORDER BY grantee, grant_entry.privilege_type",
            (_METADATA_STORE_RUNTIME_ROLE, namespace),
        ).fetchall()
    )
    relation_rows = conn.execute(
        "SELECT relation.oid, relation.relname, relation.relkind, "
        "relation.relowner = ?::pg_catalog.oid "
        "AS owner_is_source, relation.relacl IS NULL AS acl_is_default "
        "FROM pg_catalog.pg_class AS relation "
        "JOIN pg_catalog.pg_namespace AS namespace_record "
        "ON namespace_record.oid = relation.relnamespace "
        "WHERE namespace_record.nspname = ? "
        "AND relation.relkind IN ('r', 'p', 'S', 'i') "
        "ORDER BY relation.relkind, relation.relname",
        (owner_oid, namespace),
    ).fetchall()
    relations: list[dict[str, Any]] = []
    for row in relation_rows:
        if row.get("owner_is_source") is not True:
            raise PolicyCandidateAuthorityError(
                "metadata relation is not owned by the source authority owner"
            )
        relation_acl = normalized_acl(
            conn.execute(
                "SELECT CASE "
                "WHEN grant_entry.grantee = 0 THEN 'PUBLIC' "
                "WHEN grant_entry.grantee = relation.relowner "
                "THEN 'schema-owner' "
                "WHEN grantee.rolname = ? THEN 'runtime' "
                "ELSE grantee.rolname END AS grantee, "
                "grant_entry.privilege_type, grant_entry.is_grantable "
                "FROM pg_catalog.pg_class AS relation "
                "CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE("
                "relation.relacl, pg_catalog.acldefault("
                "CASE WHEN relation.relkind = 'S' THEN 'S'::\"char\" "
                "ELSE 'r'::\"char\" END, relation.relowner)"
                ")) AS grant_entry "
                "LEFT JOIN pg_catalog.pg_roles AS grantee "
                "ON grantee.oid = grant_entry.grantee "
                "WHERE relation.oid = ? "
                "ORDER BY grantee, grant_entry.privilege_type",
                (_METADATA_STORE_RUNTIME_ROLE, row["oid"]),
            ).fetchall()
        )
        relations.append(
            {
                "name": str(row["relname"]),
                "kind": str(row["relkind"]),
                "owner": "schema-owner",
                "aclIsDefault": bool(row["acl_is_default"]),
                "acl": relation_acl,
            }
        )
    function_rows = conn.execute(
        "SELECT function_record.oid, function_record.proname, "
        "function_record.proowner = "
        "?::pg_catalog.oid AS owner_is_source, "
        "function_record.proacl IS NULL AS acl_is_default, "
        "pg_catalog.pg_get_function_identity_arguments("
        "function_record.oid) AS identity_arguments "
        "FROM pg_catalog.pg_proc AS function_record "
        "JOIN pg_catalog.pg_namespace AS namespace_record "
        "ON namespace_record.oid = function_record.pronamespace "
        "WHERE namespace_record.nspname = ? "
        "ORDER BY function_record.proname, identity_arguments",
        (owner_oid, namespace),
    ).fetchall()
    functions: list[dict[str, Any]] = []
    for row in function_rows:
        if row.get("owner_is_source") is not True:
            raise PolicyCandidateAuthorityError(
                "metadata function is not owned by the source authority owner"
            )
        function_acl = normalized_acl(
            conn.execute(
                "SELECT CASE "
                "WHEN grant_entry.grantee = 0 THEN 'PUBLIC' "
                "WHEN grant_entry.grantee = function_record.proowner "
                "THEN 'schema-owner' "
                "WHEN grantee.rolname = ? THEN 'runtime' "
                "ELSE grantee.rolname END AS grantee, "
                "grant_entry.privilege_type, grant_entry.is_grantable "
                "FROM pg_catalog.pg_proc AS function_record "
                "CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE("
                "function_record.proacl, pg_catalog.acldefault("
                "'f', function_record.proowner))) AS grant_entry "
                "LEFT JOIN pg_catalog.pg_roles AS grantee "
                "ON grantee.oid = grant_entry.grantee "
                "WHERE function_record.oid = ? "
                "ORDER BY grantee, grant_entry.privilege_type",
                (_METADATA_STORE_RUNTIME_ROLE, row["oid"]),
            ).fetchall()
        )
        functions.append(
            {
                "name": str(row["proname"]),
                "identityArguments": str(row["identity_arguments"]),
                "owner": "schema-owner",
                "aclIsDefault": bool(row["acl_is_default"]),
                "acl": function_acl,
            }
        )
    try:
        triggers = postgres_trigger_manifest.schema_trigger_manifest(
            conn.raw_connection, namespace=namespace,
        )
    except ValueError as exc:
        raise PolicyCandidateAuthorityError(str(exc)) from exc
    return {
        "namespace": {
            "owner": "schema-owner",
            "aclIsDefault": bool(namespace_row["acl_is_default"]),
            "acl": namespace_acl,
        },
        "relations": relations,
        "functions": functions,
        "triggers": triggers,
    }


def _policy_candidate_authority_structure_manifest(
    conn: Any,
    *,
    tables: tuple[str, ...] | None = None,
    expected_namespace: str | None = None,
    manifest_namespace: str | None = None,
) -> dict[str, Any]:
    selected_tables = tables or _policy_candidate_authority_schema_tables(
        postgres=isinstance(conn, PostgresMetadataConnection),
    )
    if isinstance(conn, PostgresMetadataConnection):
        expected_namespace = (
            expected_namespace or _POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME
        )
        manifest_namespace = manifest_namespace or expected_namespace
        namespace = conn.execute(
            "SELECT pg_catalog.current_schema() AS current_schema, "
            "pg_catalog.current_setting('search_path') AS search_path"
        ).fetchone()
        if (
            namespace is None
            or namespace["current_schema"] != expected_namespace
            or str(namespace["search_path"]).replace('"', "")
            != (
                expected_namespace + ", pg_catalog, pg_temp"
            )
        ):
            raise PolicyCandidateAuthorityError(
                "candidate-authority PostgreSQL schema is not pinned"
            )
        function_rows = conn.execute(
            """
            SELECT function_record.oid AS function_oid,
                   function_record.proname AS function_name,
                   pg_catalog.pg_get_functiondef(function_record.oid)
                       AS definition
            FROM pg_catalog.pg_proc AS function_record
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = function_record.pronamespace
            WHERE namespace.nspname = pg_catalog.current_schema()
            ORDER BY function_record.proname,
                     pg_catalog.pg_get_function_identity_arguments(
                         function_record.oid
                     )
            """
        ).fetchall()
        functions = []
        for row in function_rows:
            function_acl = conn.execute(
                "SELECT CASE "
                "WHEN grant_entry.grantee = 0 THEN 'PUBLIC' "
                "WHEN grant_entry.grantee = function_record.proowner "
                "THEN 'schema-owner' "
                "WHEN grantee.rolname = ? THEN 'runtime' "
                "ELSE grantee.rolname END AS grantee, "
                "grant_entry.privilege_type, grant_entry.is_grantable "
                "FROM pg_catalog.pg_proc AS function_record "
                "CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE("
                "function_record.proacl, pg_catalog.acldefault("
                "'f', function_record.proowner))) AS grant_entry "
                "LEFT JOIN pg_catalog.pg_roles AS grantee "
                "ON grantee.oid = grant_entry.grantee "
                "WHERE function_record.oid = ? "
                "ORDER BY grantee, grant_entry.privilege_type",
                (_METADATA_STORE_RUNTIME_ROLE, row["function_oid"]),
            ).fetchall()
            functions.append(
                {
                    **_policy_candidate_authority_object_definition(
                        name=str(row["function_name"]),
                        definition=(
                            _policy_candidate_authority_canonicalize_namespace(
                                row["definition"],
                                actual_namespace=expected_namespace,
                                canonical_namespace=manifest_namespace,
                            )
                        ),
                    ),
                    "authority": {
                        "owner": "schema-owner",
                        "acl": [
                            {
                                "grantee": str(entry["grantee"]),
                                "privilege": str(
                                    entry["privilege_type"]
                                ),
                                "grantable": bool(
                                    entry["is_grantable"]
                                ),
                            }
                            for entry in function_acl
                        ],
                    },
                }
            )
        sequence_rows = conn.execute(
            "SELECT sequence_record.oid, sequence_record.relname "
            "FROM pg_catalog.pg_class AS sequence_record "
            "JOIN pg_catalog.pg_namespace AS namespace "
            "ON namespace.oid = sequence_record.relnamespace "
            "WHERE namespace.nspname = ? "
            "AND sequence_record.relkind = 'S' "
            "ORDER BY sequence_record.relname",
            (expected_namespace,),
        ).fetchall()
        sequences = []
        for row in sequence_rows:
            sequence_acl = conn.execute(
                "SELECT CASE "
                "WHEN grant_entry.grantee = 0 THEN 'PUBLIC' "
                "WHEN grant_entry.grantee = sequence_record.relowner "
                "THEN 'schema-owner' "
                "WHEN grantee.rolname = ? THEN 'runtime' "
                "ELSE grantee.rolname END AS grantee, "
                "grant_entry.privilege_type, grant_entry.is_grantable "
                "FROM pg_catalog.pg_class AS sequence_record "
                "CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE("
                "sequence_record.relacl, pg_catalog.acldefault("
                "'S', sequence_record.relowner))) AS grant_entry "
                "LEFT JOIN pg_catalog.pg_roles AS grantee "
                "ON grantee.oid = grant_entry.grantee "
                "WHERE sequence_record.oid = ? "
                "ORDER BY grantee, grant_entry.privilege_type",
                (_METADATA_STORE_RUNTIME_ROLE, row["oid"]),
            ).fetchall()
            sequences.append(
                {
                    "name": str(row["relname"]),
                    "authority": {
                        "owner": "schema-owner",
                        "acl": [
                            {
                                "grantee": str(entry["grantee"]),
                                "privilege": str(
                                    entry["privilege_type"]
                                ),
                                "grantable": bool(
                                    entry["is_grantable"]
                                ),
                            }
                            for entry in sequence_acl
                        ],
                    },
                }
            )
        backend = "postgres"
        namespace_name = manifest_namespace
        object_authority = (
            _policy_candidate_authority_postgres_object_authority(
                conn,
                namespace=expected_namespace,
            )
        )
    else:
        functions = []
        sequences = []
        backend = "sqlite"
        namespace_name = "main"
        object_authority = None
    return {
        "contract": _POLICY_CANDIDATE_AUTHORITY_SCHEMA_CONTRACT,
        "backend": backend,
        "namespace": namespace_name,
        "tables": [
            _policy_candidate_authority_table_manifest(
                conn,
                table,
                canonical_namespace=(
                    manifest_namespace
                    if isinstance(conn, PostgresMetadataConnection)
                    else None
                ),
            )
            for table in selected_tables
        ],
        "functions": functions,
        "sequences": sequences,
        "objectAuthority": object_authority,
    }


def _policy_candidate_authority_manifest_digest(
    manifest: Mapping[str, Any],
) -> tuple[str, str]:
    manifest_json = dumps(dict(manifest))
    if (
        len(manifest_json.encode("utf-8"))
        > _POLICY_AUTHORITY_MAX_CANONICAL_AGGREGATE_BYTES
    ):
        raise PolicyCandidateAuthorityError(
            "candidate-authority structural manifest is too large"
        )
    return (
        manifest_json,
        _policy_candidate_authority_framed_digest(
            "serverware.policyCandidateAuthorityStructuralManifest/v1",
            manifest_json.encode("utf-8"),
        ),
    )


def _policy_candidate_authority_required_guard_names(
    *, postgres: bool
) -> tuple[set[str], set[str]]:
    trigger_names = {
        _policy_candidate_authority_object_name(
            "serverware",
            "policy_canary_revisions",
            "transition",
            "binding",
        ),
        _policy_candidate_authority_object_name(
            "serverware",
            "policy_canary_instance_revisions",
            "transition",
            "binding",
        ),
        _policy_candidate_authority_object_name(
            "serverware",
            "policy_activation_revisions",
            "transition",
            "binding",
        ),
        "serverware_policy_authority_trusted_key_heads_successor",
        "serverware_policy_authority_key_revocation_sequence",
        "serverware_policy_runtime_role_key_revocation_sequence",
        "serverware_policy_canary_checkpoint_heads_successor",
        "serverware_policy_checkpoint_append_guard",
        "serverware_policy_authority_verifier_commit_deadline",
        "serverware_policy_authority_writer_commit_deadline",
    }
    function_names: set[str] = set()
    for table in (
        _POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES
        + _POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES
    ):
        trigger_names.add(
            _policy_candidate_authority_object_name(
                "serverware", table, "canonical", "insert"
            )
        )
        if postgres:
            if table in _POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES:
                trigger_names.add(
                    _policy_candidate_authority_object_name(
                        "serverware", table, "immutable"
                    )
                )
        else:
            if table in _POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES:
                trigger_names.add(
                    _policy_candidate_authority_object_name(
                        "serverware", table, "canonical", "update"
                    )
                )
            if table in _POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES:
                trigger_names.add(
                    _policy_candidate_authority_object_name(
                        "serverware", table, "immutable", "update"
                    )
                )
                trigger_names.add(
                    _policy_candidate_authority_object_name(
                        "serverware", table, "immutable", "delete"
                    )
                )
    for head_table in (
        "policy_canary_heads",
        "policy_canary_instance_heads",
        "policy_activation_heads",
    ):
        trigger_names.add(f"serverware_{head_table}_successor")
    if postgres:
        for entries in _POLICY_AUTHORITY_OPERATION_QUERY_MANIFEST.values():
            for entry in entries:
                trigger_names.add(
                    _policy_candidate_authority_object_name(
                        "serverware",
                        str(entry["table"]),
                        "authenticated",
                    )
                )
        trigger_names.update(
            {
                "serverware_policy_high_water_activation_guard",
                "serverware_policy_publications_activation_guard",
            }
        )
        function_names.update(
            {
                "serverware_reject_policy_authority_mutation",
                "serverware_validate_policy_authority_insert",
                "serverware_guard_policy_revision_transition",
                "serverware_guard_policy_authority_trusted_key_head",
                "serverware_guard_policy_authority_key_revocation_sequence",
                "serverware_guard_policy_runtime_role_key_revocation_sequence",
                "serverware_guard_policy_checkpoint_head",
                "serverware_guard_policy_checkpoint_append",
                "serverware_guard_policy_canary_heads_successor",
                "serverware_guard_policy_canary_instance_heads_successor",
                "serverware_guard_policy_activation_heads_successor",
                "serverware_guard_policy_activation_publication",
                "serverware_policy_authority_canonical_json",
                *WIRE_JSON_FUNCTION_NAMES,
                AUDIT_CAPACITY_FUNCTION_NAME,
                *authority_contract.POSTGRES_COUNTED_FUNCTION_SIGNATURES,
                "serverware_policy_authority_domain_digest",
                "serverware_policy_authority_framed_digest",
                "serverware_policy_authority_authenticated_empty",
                "serverware_policy_authority_authenticated_apply",
                "serverware_policy_authority_authenticated_trigger",
                "serverware_rbac_binding_revision",
                "serverware_metadata_storage_epoch_guard",
                *_POLICY_AUTHORITY_EXECUTOR_FUNCTIONS,
                *_POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTIONS,
            }
        )
        overlong = sorted(
            name
            for name in trigger_names | function_names
            if len(name.encode("ascii")) > 63
        )
        if overlong:
            raise PolicyCandidateAuthorityError(
                "candidate-authority PostgreSQL object name exceeds 63 "
                "bytes: " + ", ".join(overlong)
            )
    return trigger_names, function_names


def _policy_candidate_authority_expected_structure_manifest(
    conn: Any,
    *,
    source_schema_program: str,
    legacy_completed_v9_receipt: bool = False,
) -> dict[str, Any]:
    try:
        require_metadata_schema_program(
            source_schema_program,
            legacy_completed_v9_receipt=legacy_completed_v9_receipt,
        )
    except ValueError as exc:
        raise PolicyCandidateAuthorityError(
            "candidate-authority source schema declaration is not exact"
        ) from exc
    if isinstance(conn, PostgresMetadataConnection):
        scratch_schema = "serverware_candidate_authority_expected_v9"
        existing = conn.execute(
            "SELECT pg_catalog.to_regnamespace(?) IS NOT NULL AS present",
            (scratch_schema,),
        ).fetchone()
        if existing is None or bool(existing["present"]):
            raise PolicyCandidateAuthorityError(
                "candidate-authority expected-schema namespace is not pristine"
            )
        conn.execute("SAVEPOINT serverware_candidate_expected")
        try:
            conn.execute(
                "CREATE SCHEMA "
                + _policy_candidate_authority_identifier(scratch_schema)
                + " AUTHORIZATION CURRENT_USER"
            )
            conn.execute(
                "REVOKE ALL ON SCHEMA "
                + _policy_candidate_authority_identifier(scratch_schema)
                + " FROM PUBLIC"
            )
            conn.execute(
                "SET LOCAL search_path TO "
                + _policy_candidate_authority_identifier(scratch_schema)
                + ", pg_catalog, pg_temp"
            )
            _execute_metadata_schema_statements(
                conn, source_schema_program
            )
            _finalize_policy_candidate_authority_outbox_contract(conn)
            _install_policy_candidate_authority_guards(conn)
            _install_rbac_binding_revision_triggers(conn)
            _install_metadata_storage_epoch_guards(conn)
            _seal_postgres_schema_acl(
                conn._conn,
                schema=scratch_schema,
                runtime_role=_METADATA_STORE_RUNTIME_ROLE,
                table_privileges=(
                    "SELECT",
                    "INSERT",
                    "UPDATE",
                    "DELETE",
                ),
                authority_executor_role=(
                    _METADATA_STORE_AUTHORITY_EXECUTOR_ROLE
                ),
                authority_verifier_role=_METADATA_STORE_AUTHORITY_VERIFIER_ROLE,
                authority_verifier_read_tables=_POLICY_AUTHORITY_VERIFIER_READ_TABLES,
                authority_owner_role=(
                    _METADATA_STORE_AUTHORITY_OWNER_ROLE
                ),
                authority_capability_issuer_role=(
                    _METADATA_STORE_AUTHORITY_CAPABILITY_ISSUER_ROLE
                ),
                runtime_read_only_tables=(
                    _POLICY_AUTHORITY_RUNTIME_READ_ONLY_TABLES
                ),
                authority_executor_function_signatures=(
                    _POLICY_AUTHORITY_EXECUTOR_FUNCTION_SIGNATURES
                ),
                authority_planner_writer_role=(
                    _METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE
                ),
                authority_capability_issuer_functions=(
                    _POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTIONS
                ),
                authority_planner_writer_table_privileges=(
                    _POLICY_AUTHORITY_PLANNER_WRITER_TABLE_PRIVILEGES
                ),
                authority_planner_writer_function_signatures=(
                    AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES
                ),
            )
            expected = _policy_candidate_authority_structure_manifest(
                conn,
                expected_namespace=scratch_schema,
                manifest_namespace=(
                    _POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME
                ),
            )
        finally:
            conn.execute(
                "ROLLBACK TO SAVEPOINT serverware_candidate_expected"
            )
            conn.execute(
                "RELEASE SAVEPOINT serverware_candidate_expected"
            )
        restored = conn.execute(
            "SELECT pg_catalog.current_schema() AS current_schema, "
            "pg_catalog.current_setting('search_path') AS search_path"
        ).fetchone()
        if (
            restored is None
            or restored["current_schema"]
            != _POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME
            or str(restored["search_path"]).replace('"', "")
            != (
                _POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME
                + ", pg_catalog, pg_temp"
            )
        ):
            raise PolicyCandidateAuthorityError(
                "candidate-authority expected-schema derivation changed "
                "the pinned PostgreSQL namespace"
            )
        return expected

    expected_conn = sqlite3.connect(":memory:")
    expected_conn.row_factory = sqlite3.Row
    try:
        expected_conn.execute("PRAGMA foreign_keys=ON")
        _sqlite_execute_fixed_statements(
            expected_conn, source_schema_program
        )
        _finalize_policy_candidate_authority_outbox_contract(
            expected_conn
        )
        _install_policy_candidate_authority_guards(expected_conn)
        _install_rbac_binding_revision_triggers(expected_conn)
        _install_metadata_storage_epoch_guards(expected_conn)
        return _policy_candidate_authority_structure_manifest(
            expected_conn
        )
    finally:
        expected_conn.close()


def _validate_policy_candidate_authority_structure(
    conn: Any,
    *,
    require_recorded_contract: bool,
    source_schema_program: str | None = None,
) -> tuple[str, str]:
    manifest = _policy_candidate_authority_structure_manifest(conn)
    table_manifests = {
        str(table["name"]): table for table in manifest["tables"]
    }
    missing = sorted(
        table
        for table, table_manifest in table_manifests.items()
        if not table_manifest["present"]
    )
    if missing:
        raise PolicyCandidateAuthorityError(
            "candidate-authority structural manifest is missing tables: "
            + ", ".join(missing)
        )
    if isinstance(conn, PostgresMetadataConnection):
        for table, expected_columns in authority_contract.POSTGRES_COUNTED_STORE_COLUMNS.items():
            columns = table_manifests[table]["columns"]
            if (tuple(column["name"] for column in columns) != expected_columns
                    or any(column["nullable"] for column in columns)):
                raise PolicyCandidateAuthorityError(
                    "counted custody columns are not source exact: " + table
                )
    for table in (
        _POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES
        + _POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES
    ):
        if not table_manifests[table]["primaryKey"]:
            raise PolicyCandidateAuthorityError(
                f"candidate-authority table {table} has no primary key"
            )
    outbox = table_manifests["metadata_audit_outbox"]
    outbox_columns = {
        str(column["name"]): column for column in outbox["columns"]
    }
    for column in ("id", "event_json", "event_digest"):
        if column not in outbox_columns or outbox_columns[column]["nullable"]:
            raise PolicyCandidateAuthorityError(
                "metadata audit outbox digest identity is incomplete"
            )
    digest_indexes = [
        index
        for index in outbox["indexes"]
        if index["unique"]
        and not index.get("partial", False)
        and list(index["columns"]) == ["id", "event_digest"]
    ]
    if not digest_indexes:
        raise PolicyCandidateAuthorityError(
            "metadata audit outbox lacks UNIQUE(id,event_digest)"
        )
    for index in outbox["indexes"]:
        if (
            "event_json" in index["columns"]
            or re.search(
                r"(?<![a-z0-9_])event_json(?![a-z0-9_])",
                str(index["definition"]).lower(),
            )
        ):
            raise PolicyCandidateAuthorityError(
                "metadata audit outbox still indexes full event_json"
            )
    transition = table_manifests["policy_authority_transition_audits"]
    transition_fks = [
        constraint
        for constraint in transition["constraints"]
        if constraint["type"] == "f"
        and constraint["columns"]
        == ["outbox_id", "outbox_event_digest"]
        and constraint["foreignTable"] == "metadata_audit_outbox"
        and constraint["foreignColumns"] == ["id", "event_digest"]
    ]
    if len(transition_fks) != 1:
        raise PolicyCandidateAuthorityError(
            "candidate-authority transition outbox FK is not exact"
        )
    actual_trigger_names = {
        str(trigger["name"])
        for table in table_manifests.values()
        for trigger in table["triggers"]
    }
    actual_function_names = {
        str(function["name"]) for function in manifest["functions"]
    }
    required_triggers, required_functions = (
        _policy_candidate_authority_required_guard_names(
            postgres=isinstance(conn, PostgresMetadataConnection)
        )
    )
    missing_triggers = sorted(required_triggers - actual_trigger_names)
    missing_functions = sorted(required_functions - actual_function_names)
    if missing_triggers or missing_functions:
        raise PolicyCandidateAuthorityError(
            "candidate-authority guard manifest is incomplete: "
            + ", ".join(missing_triggers + missing_functions)
        )
    if source_schema_program is not None:
        expected_manifest = (
            _policy_candidate_authority_expected_structure_manifest(
                conn,
                source_schema_program=source_schema_program,
            )
        )
    else:
        if not require_recorded_contract:
            raise PolicyCandidateAuthorityError(
                "fresh candidate-authority validation requires the "
                "immutable source schema declaration"
            )
        expected_rows = conn.execute(
            "SELECT structural_manifest_json "
            "FROM policy_authority_schema_contracts "
            "WHERE schema_version = ? LIMIT 2",
            (_POLICY_CANDIDATE_AUTHORITY_SCHEMA_VERSION,),
        ).fetchall()
        if len(expected_rows) != 1:
            raise PolicyCandidateAuthorityError(
                "candidate-authority source-pinned manifest is missing"
            )
        expected_manifest_json = _candidate_authority_canonical_json(
            "candidate-authority source-pinned structural manifest",
            str(expected_rows[0]["structural_manifest_json"]),
        )
        expected_manifest = loads(expected_manifest_json, None)
        if not isinstance(expected_manifest, dict):
            raise PolicyCandidateAuthorityError(
                "candidate-authority source-pinned manifest is invalid"
            )
    if manifest != expected_manifest:
        raise PolicyCandidateAuthorityError(
            "candidate-authority live structure differs from the exact "
            "source-pinned columns, types, nullability, defaults, keys, "
            "constraints, indexes, triggers, or functions"
        )
    manifest_json, manifest_digest = (
        _policy_candidate_authority_manifest_digest(expected_manifest)
    )
    if require_recorded_contract:
        row = conn.execute(
            "SELECT schema_version, contract_id, source_revision, "
            "source_contract_digest, structural_manifest_json, "
            "structural_manifest_digest "
            "FROM policy_authority_schema_contracts "
            "WHERE schema_version = ? LIMIT 2",
            (_POLICY_CANDIDATE_AUTHORITY_SCHEMA_VERSION,),
        ).fetchall()
        if len(row) != 1:
            raise PolicyCandidateAuthorityError(
                "candidate-authority schema contract record is missing"
            )
        contract = row[0]
        expected = {
            "schema_version": _POLICY_CANDIDATE_AUTHORITY_SCHEMA_VERSION,
            "contract_id": _POLICY_CANDIDATE_AUTHORITY_SCHEMA_CONTRACT,
            "source_revision": _POLICY_CANDIDATE_AUTHORITY_SOURCE_REVISION,
            "source_contract_digest": (
                _policy_candidate_authority_source_contract_digest()
            ),
            "structural_manifest_json": manifest_json,
            "structural_manifest_digest": manifest_digest,
        }
        for field, value in expected.items():
            if contract[field] != value:
                raise PolicyCandidateAuthorityError(
                    "candidate-authority recorded schema contract does not "
                    f"match live {field}"
                )
        if isinstance(conn, PostgresMetadataConnection):
            with conn.raw_connection.cursor() as cur:
                live_owner_contract = (
                    _validate_policy_authority_owner_apply_function(cur)
                )
            owner_contract_rows = conn.execute(
                "SELECT contract_id, schema_version, source_revision, "
                "function_name, function_definition_digest, "
                "verifier_spki_digest, verifier_measurement_digest, "
                "verification_profile_digest, response_max_bytes, "
                "response_max_age_ns, max_clock_skew_ns "
                "FROM policy_authority_owner_contracts "
                "WHERE contract_id = ? LIMIT 2",
                (_POLICY_AUTHORITY_OWNER_CONTRACT_ID,),
            ).fetchall()
            if (
                len(owner_contract_rows) != 1
                or any(
                    owner_contract_rows[0][field] != value
                    for field, value in live_owner_contract.items()
                )
            ):
                raise PolicyCandidateAuthorityError(
                    "recorded owner policy-authority implementation differs "
                    "from its live pinned transaction handler"
                )
    return manifest_json, manifest_digest


def _policy_candidate_authority_offline_required(
    *, version: int, detail: str
) -> None:
    raise PolicyCandidateAuthorityOfflineMigrationRequired(
        {
            "contractId":
                _POLICY_CANDIDATE_AUTHORITY_OFFLINE_MIGRATION_CONTRACT_ID,
            "detail": detail,
            "inspectionApi":
                "inspect_policy_candidate_authority_offline_migration",
            "migrationApi": "migrate_policy_candidate_authority_offline",
            "sourceVersion": version,
            "targetVersion": _POLICY_CANDIDATE_AUTHORITY_SCHEMA_VERSION,
        }
    )


def _policy_candidate_authority_table_has_rows(
    conn: Any, table: str
) -> bool:
    quoted_table = _policy_candidate_authority_identifier(table)
    return (
        conn.execute(f"SELECT 1 FROM {quoted_table} LIMIT 1").fetchone()
        is not None
    )


def record_policy_candidate_authority_v8_to_v9_receipt(
    *,
    migration_sha256: str,
    before_manifest_json: str,
    before_row_counts_json: str,
    after_manifest_json: str,
    after_row_counts_json: str,
    signer_public_key_base64url: str,
    detached_signature: str,
    completed_at: str,
    connection: Any,
) -> dict[str, Any]:
    digest_pattern = r"sha256:[0-9a-f]{64}"
    if (
        re.fullmatch(digest_pattern, migration_sha256) is None
        or not isinstance(completed_at, str)
        or not completed_at
        or len(completed_at.encode("utf-8")) > 256
        or any(character in completed_at for character in "\x00\r\n")
    ):
        raise PolicyCandidateAuthorityError(
            "candidate-authority migration identity is invalid"
        )
    canonical_documents: dict[str, str] = {}
    parsed_documents: dict[str, Any] = {}
    for label, document in (
        ("before migration manifest", before_manifest_json),
        ("before migration row counts", before_row_counts_json),
        ("after migration manifest", after_manifest_json),
        ("after migration row counts", after_row_counts_json),
    ):
        canonical = _candidate_authority_canonical_json(
            label,
            document,
        )
        parsed = loads(canonical, None)
        if not isinstance(parsed, dict):
            raise PolicyCandidateAuthorityError(
                f"candidate-authority {label} is not an object"
            )
        canonical_documents[label] = canonical
        parsed_documents[label] = parsed
    del parsed_documents
    before_manifest_json = canonical_documents[
        "before migration manifest"
    ]
    before_row_counts_json = canonical_documents[
        "before migration row counts"
    ]
    after_manifest_json = canonical_documents[
        "after migration manifest"
    ]
    after_row_counts_json = canonical_documents[
        "after migration row counts"
    ]
    before_manifest_digest = _policy_candidate_authority_framed_digest(
        authority_contract.MIGRATION_MANIFEST_DIGEST_DOMAIN,
        before_manifest_json.encode("ascii"),
    )
    before_row_counts_digest = _policy_candidate_authority_framed_digest(
        authority_contract.MIGRATION_ROWS_DIGEST_DOMAIN,
        before_row_counts_json.encode("ascii"),
    )
    after_manifest_digest = _policy_candidate_authority_framed_digest(
        authority_contract.MIGRATION_MANIFEST_DIGEST_DOMAIN,
        after_manifest_json.encode("ascii"),
    )
    after_row_counts_digest = _policy_candidate_authority_framed_digest(
        authority_contract.MIGRATION_ROWS_DIGEST_DOMAIN,
        after_row_counts_json.encode("ascii"),
    )
    signer_public_key = _policy_candidate_authority_decode_base64url(
        signer_public_key_base64url,
        label="candidate-authority migration signer",
        size=32,
    )
    signature = _policy_candidate_authority_decode_base64url(
        detached_signature,
        label="candidate-authority migration signature",
        size=64,
    )
    signer_identity_digest = _policy_candidate_authority_framed_digest(
        authority_contract.MIGRATION_SIGNER_IDENTITY_DOMAIN,
        signer_public_key,
    )
    receipt = {
        "schema": authority_contract.MIGRATION_RECEIPT_SCHEMA,
        "contractId": authority_contract.V8_TO_V9_MIGRATION_CONTRACT_ID,
        "migrationName": authority_contract.V8_TO_V9_MIGRATION_NAME,
        "sourceVersion": 8,
        "targetVersion": 9,
        "migrationSha256": migration_sha256,
        "sourceRevision": authority_contract.SOURCE_REVISION,
        "operationContractDigest":
            authority_contract.OPERATION_MANIFEST_DIGEST,
        "signerIdentityDigest": signer_identity_digest,
        "beforeManifestDigest": before_manifest_digest,
        "beforeRowCountsDigest": before_row_counts_digest,
        "afterManifestDigest": after_manifest_digest,
        "afterRowCountsDigest": after_row_counts_digest,
        "terminal": True,
        "status": "completed",
        "completedAt": completed_at,
    }
    receipt_json = json.dumps(
        receipt,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    receipt_digest = _policy_candidate_authority_framed_digest(
        authority_contract.MIGRATION_RECEIPT_DIGEST_DOMAIN,
        receipt_json.encode("ascii"),
    )
    signature_digest = "sha256:" + hashlib.sha256(signature).hexdigest()
    signing_digest = _policy_candidate_authority_framed_digest(
        authority_contract.MIGRATION_RECEIPT_SIGNATURE_DOMAIN,
        receipt_json.encode("ascii"),
    )
    try:
        Ed25519PublicKey.from_public_bytes(signer_public_key).verify(
            signature,
            signing_digest.encode("ascii"),
        )
    except InvalidSignature as exc:
        raise PolicyCandidateAuthorityError(
            "candidate-authority migration receipt signature is invalid"
        ) from exc
    expected_row = {
        "contract_id": authority_contract.V8_TO_V9_MIGRATION_CONTRACT_ID,
        "source_version": 8,
        "target_version": 9,
        "migration_name": authority_contract.V8_TO_V9_MIGRATION_NAME,
        "migration_sha256": migration_sha256,
        "source_revision": authority_contract.SOURCE_REVISION,
        "before_manifest_json": before_manifest_json,
        "before_manifest_digest": before_manifest_digest,
        "before_row_counts_json": before_row_counts_json,
        "before_row_counts_digest": before_row_counts_digest,
        "after_manifest_json": after_manifest_json,
        "after_manifest_digest": after_manifest_digest,
        "after_row_counts_json": after_row_counts_json,
        "after_row_counts_digest": after_row_counts_digest,
        "operation_contract_digest":
            authority_contract.OPERATION_MANIFEST_DIGEST,
        "receipt_json": receipt_json,
        "receipt_digest": receipt_digest,
        "signer_identity_digest": signer_identity_digest,
        "signer_public_key_base64url": signer_public_key_base64url,
        "signature_algorithm": "Ed25519",
        "detached_signature": detached_signature,
        "detached_signature_digest": signature_digest,
        "status": "completed",
        "completed_at": completed_at,
    }
    existing = _policy_candidate_authority_offline_receipt(
        connection,
        source_version=8,
    )
    if existing is not None:
        if any(
            existing[field] != value
            for field, value in expected_row.items()
        ):
            raise PolicyCandidateAuthorityError(
                "candidate-authority migration receipt retry is not exact"
            )
        return {
            "receipt": receipt,
            "receiptDigest": receipt_digest,
            "status": "completed",
            "exactReplay": True,
        }
    columns = tuple(expected_row)
    connection.execute(
        "INSERT INTO policy_authority_v9_offline_migration_receipts ("
        + ", ".join(columns)
        + ") VALUES ("
        + ", ".join("?" for _column in columns)
        + ")",
        tuple(expected_row[column] for column in columns),
    )
    recorded = _policy_candidate_authority_offline_receipt(
        connection,
        source_version=8,
    )
    if recorded is None or any(
        recorded[field] != value
        for field, value in expected_row.items()
    ):
        raise PolicyCandidateAuthorityError(
            "candidate-authority migration receipt was not exact"
        )
    return {
        "receipt": receipt,
        "receiptDigest": receipt_digest,
        "status": "completed",
        "exactReplay": False,
    }


def _policy_candidate_authority_offline_receipt(
    conn: Any, *, source_version: int
) -> Any:
    table = "policy_authority_v9_offline_migration_receipts"
    if not _metadata_table_exists(conn, table):
        return None
    columns = {
        str(column["name"])
        for column in _policy_candidate_authority_table_manifest(
            conn, table
        )["columns"]
    }
    required = {
        "contract_id",
        "source_version",
        "target_version",
        "migration_name",
        "migration_sha256",
        "source_revision",
        "before_manifest_json",
        "before_manifest_digest",
        "before_row_counts_json",
        "before_row_counts_digest",
        "after_manifest_json",
        "after_manifest_digest",
        "after_row_counts_json",
        "after_row_counts_digest",
        "operation_contract_digest",
        "status",
        "receipt_json",
        "receipt_digest",
        "signer_identity_digest",
        "signer_public_key_base64url",
        "signature_algorithm",
        "detached_signature",
        "detached_signature_digest",
        "completed_at",
    }
    if not required.issubset(columns):
        raise PolicyCandidateAuthorityError(
            "candidate-authority offline migration receipt schema is invalid"
        )
    rows = conn.execute(
        "SELECT contract_id, source_version, target_version, "
        "migration_name, migration_sha256, source_revision, "
        "before_manifest_json, before_manifest_digest, "
        "before_row_counts_json, before_row_counts_digest, "
        "after_manifest_json, after_manifest_digest, "
        "after_row_counts_json, after_row_counts_digest, "
        "operation_contract_digest, status, receipt_json, "
        "receipt_digest, signer_identity_digest, signature_algorithm, "
        "signer_public_key_base64url, detached_signature, "
        "detached_signature_digest, completed_at "
        "FROM policy_authority_v9_offline_migration_receipts "
        "WHERE contract_id = ? LIMIT 2",
        (_POLICY_CANDIDATE_AUTHORITY_OFFLINE_MIGRATION_CONTRACT_ID,),
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise PolicyCandidateAuthorityError(
            "candidate-authority offline migration receipt is ambiguous"
        )
    row = rows[0]
    receipt_json = _candidate_authority_canonical_json(
        "candidate-authority v9 offline migration receipt",
        str(row["receipt_json"]),
    )
    receipt = loads(receipt_json, None)
    canonical_documents = {
        "before_manifest_json":
            _candidate_authority_canonical_json(
                "candidate-authority before migration manifest",
                str(row["before_manifest_json"]),
            ),
        "before_row_counts_json":
            _candidate_authority_canonical_json(
                "candidate-authority before migration row counts",
                str(row["before_row_counts_json"]),
            ),
        "after_manifest_json":
            _candidate_authority_canonical_json(
                "candidate-authority after migration manifest",
                str(row["after_manifest_json"]),
            ),
        "after_row_counts_json":
            _candidate_authority_canonical_json(
                "candidate-authority after migration row counts",
                str(row["after_row_counts_json"]),
            ),
    }
    if (
        row["contract_id"]
            != authority_contract.V8_TO_V9_MIGRATION_CONTRACT_ID
        or int(row["source_version"]) != source_version
        or int(row["target_version"])
        != _POLICY_CANDIDATE_AUTHORITY_SCHEMA_VERSION
        or row["migration_name"]
            != authority_contract.V8_TO_V9_MIGRATION_NAME
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            str(row["migration_sha256"]),
        )
            is None
        or row["source_revision"] != authority_contract.SOURCE_REVISION
        or row["operation_contract_digest"]
        != authority_contract.OPERATION_MANIFEST_DIGEST
        or row["status"] != "completed"
        or not isinstance(receipt, dict)
        or set(receipt)
            != {
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
        or receipt.get("schema")
            != authority_contract.MIGRATION_RECEIPT_SCHEMA
        or receipt.get("contractId")
            != authority_contract.V8_TO_V9_MIGRATION_CONTRACT_ID
        or receipt.get("migrationName")
            != authority_contract.V8_TO_V9_MIGRATION_NAME
        or receipt.get("migrationName") != row["migration_name"]
        or int(receipt.get("sourceVersion", -1)) != source_version
        or int(receipt.get("targetVersion", -1))
            != _POLICY_CANDIDATE_AUTHORITY_SCHEMA_VERSION
        or receipt.get("sourceRevision")
            != _POLICY_CANDIDATE_AUTHORITY_SOURCE_REVISION
        or receipt.get("sourceRevision") != row["source_revision"]
        or receipt.get("migrationSha256") != row["migration_sha256"]
        or receipt.get("operationContractDigest")
            != authority_contract.OPERATION_MANIFEST_DIGEST
        or receipt.get("signerIdentityDigest")
            != row["signer_identity_digest"]
        or receipt.get("beforeManifestDigest")
            != row["before_manifest_digest"]
        or receipt.get("beforeRowCountsDigest")
            != row["before_row_counts_digest"]
        or receipt.get("afterManifestDigest")
            != row["after_manifest_digest"]
        or receipt.get("afterRowCountsDigest")
            != row["after_row_counts_digest"]
        or receipt.get("status") != "completed"
        or receipt.get("terminal") is not True
        or receipt.get("completedAt") != row["completed_at"]
        or any(
            canonical_documents[field] != row[field]
            for field in canonical_documents
        )
        or row["before_manifest_digest"]
            != _policy_candidate_authority_framed_digest(
                authority_contract.MIGRATION_MANIFEST_DIGEST_DOMAIN,
                canonical_documents["before_manifest_json"].encode(
                    "ascii"
                ),
            )
        or row["before_row_counts_digest"]
            != _policy_candidate_authority_framed_digest(
                authority_contract.MIGRATION_ROWS_DIGEST_DOMAIN,
                canonical_documents["before_row_counts_json"].encode(
                    "ascii"
                ),
            )
        or row["after_manifest_digest"]
            != _policy_candidate_authority_framed_digest(
                authority_contract.MIGRATION_MANIFEST_DIGEST_DOMAIN,
                canonical_documents["after_manifest_json"].encode(
                    "ascii"
                ),
            )
        or row["after_row_counts_digest"]
            != _policy_candidate_authority_framed_digest(
                authority_contract.MIGRATION_ROWS_DIGEST_DOMAIN,
                canonical_documents["after_row_counts_json"].encode(
                    "ascii"
                ),
            )
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            str(receipt.get("migrationSha256")),
        )
            is None
        or row["receipt_digest"]
            != _policy_candidate_authority_framed_digest(
                authority_contract.MIGRATION_RECEIPT_DIGEST_DOMAIN,
                receipt_json.encode("ascii"),
            )
        or row["signature_algorithm"] != "Ed25519"
        or not isinstance(row["detached_signature"], str)
        or not row["detached_signature"]
        or any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", str(row[field]))
            is None
            for field in (
                "before_manifest_digest",
                "before_row_counts_digest",
                "after_manifest_digest",
                "after_row_counts_digest",
                "receipt_digest",
                "signer_identity_digest",
                "detached_signature_digest",
            )
        )
    ):
        raise PolicyCandidateAuthorityError(
            "candidate-authority offline migration receipt is not exact"
        )
    public_key = _policy_candidate_authority_decode_base64url(
        row["signer_public_key_base64url"],
        label="candidate-authority migration signer",
        size=32,
    )
    signature = _policy_candidate_authority_decode_base64url(
        row["detached_signature"],
        label="candidate-authority migration signature",
        size=64,
    )
    if (
        row["signer_identity_digest"]
        != _policy_candidate_authority_framed_digest(
            authority_contract.MIGRATION_SIGNER_IDENTITY_DOMAIN,
            public_key,
        )
        or row["detached_signature_digest"]
            != "sha256:" + hashlib.sha256(signature).hexdigest()
    ):
        raise PolicyCandidateAuthorityError(
            "candidate-authority migration signer binding is invalid"
        )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            _policy_candidate_authority_framed_digest(
                authority_contract.MIGRATION_RECEIPT_SIGNATURE_DOMAIN,
                receipt_json.encode("ascii"),
            ).encode("ascii"),
        )
    except InvalidSignature as exc:
        raise PolicyCandidateAuthorityError(
            "candidate-authority migration receipt signature is invalid"
        ) from exc
    return row


def _completed_v9_receipt_schema_programs(
    source_schema_program: str,
    *,
    connection: Any,
) -> tuple[str, str, dict[str, Any], dict[str, Any]]:
    try:
        target_table_source, legacy_schema_program = completed_v9_schema_programs(
            source_schema_program
        )
    except ValueError as exc:
        raise PolicyCandidateAuthorityError(
            "completed-v9 repair target source is not exact"
        ) from exc
    target_manifest = _policy_candidate_authority_expected_structure_manifest(
        connection,
        source_schema_program=source_schema_program,
    )
    legacy_manifest = _policy_candidate_authority_expected_structure_manifest(
        connection,
        source_schema_program=legacy_schema_program,
        legacy_completed_v9_receipt=True,
    )
    return (
        target_table_source,
        legacy_schema_program,
        target_manifest,
        legacy_manifest,
    )


def _completed_v9_legacy_receipt(
    connection: Any,
    *,
    signer_public_key_base64url: str,
) -> dict[str, Any]:
    columns = (
        "contract_id",
        "source_version",
        "target_version",
        "before_manifest_json",
        "before_manifest_digest",
        "before_row_counts_json",
        "before_row_counts_digest",
        "after_manifest_json",
        "after_manifest_digest",
        "after_row_counts_json",
        "after_row_counts_digest",
        "operation_contract_digest",
        "receipt_json",
        "receipt_digest",
        "signer_identity_digest",
        "signature_algorithm",
        "detached_signature",
        "detached_signature_digest",
        "status",
        "completed_at",
    )
    rows = connection.execute(
        "SELECT "
        + ", ".join(columns)
        + " FROM policy_authority_v9_offline_migration_receipts "
        "WHERE contract_id = ? LIMIT 2",
        (authority_contract.V8_TO_V9_MIGRATION_CONTRACT_ID,),
    ).fetchall()
    if len(rows) != 1:
        raise PolicyCandidateAuthorityError(
            "completed-v9 legacy migration receipt is missing or ambiguous"
        )
    row = dict(rows[0])
    canonical_documents: dict[str, str] = {}
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
    for json_column, digest_column, domain in digest_bindings:
        canonical = _candidate_authority_canonical_json(
            "completed-v9 legacy " + json_column,
            str(row[json_column]),
        )
        if (
            not isinstance(loads(canonical, None), dict)
            or row[digest_column]
            != _policy_candidate_authority_framed_digest(
                domain,
                canonical.encode("ascii"),
            )
        ):
            raise PolicyCandidateAuthorityError(
                "completed-v9 legacy migration evidence is not exact"
            )
        canonical_documents[json_column] = canonical
    receipt_json = _candidate_authority_canonical_json(
        "completed-v9 legacy receipt",
        str(row["receipt_json"]),
    )
    receipt = loads(receipt_json, None)
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
    public_key = _policy_candidate_authority_decode_base64url(
        signer_public_key_base64url,
        label="completed-v9 repair signer",
        size=32,
    )
    legacy_signature = _policy_candidate_authority_decode_base64url(
        row["detached_signature"],
        label="completed-v9 legacy signature",
        size=64,
    )
    expected_signer_identity = _policy_candidate_authority_framed_digest(
        authority_contract.MIGRATION_SIGNER_IDENTITY_DOMAIN,
        public_key,
    )
    if (
        row["contract_id"]
        != authority_contract.V8_TO_V9_MIGRATION_CONTRACT_ID
        or int(row["source_version"]) != 8
        or int(row["target_version"]) != 9
        or row["operation_contract_digest"]
        != authority_contract.OPERATION_MANIFEST_DIGEST
        or row["status"] != "completed"
        or not isinstance(row["completed_at"], str)
        or not row["completed_at"]
        or len(row["completed_at"].encode("utf-8")) > 256
        or any(character in row["completed_at"] for character in "\x00\r\n")
        or not isinstance(receipt, dict)
        or set(receipt) != legacy_receipt_fields
        or receipt.get("contractId")
        != authority_contract.V8_TO_V9_MIGRATION_CONTRACT_ID
        or int(receipt.get("sourceVersion", -1)) != 8
        or int(receipt.get("targetVersion", -1)) != 9
        or receipt.get("sourceRevision") != authority_contract.SOURCE_REVISION
        or receipt.get("operationContractDigest")
        != authority_contract.OPERATION_MANIFEST_DIGEST
        or receipt.get("beforeManifestDigest")
        != row["before_manifest_digest"]
        or receipt.get("beforeRowCountsDigest")
        != row["before_row_counts_digest"]
        or receipt.get("afterManifestDigest")
        != row["after_manifest_digest"]
        or receipt.get("afterRowCountsDigest")
        != row["after_row_counts_digest"]
        or receipt.get("status") != "completed"
        or row["receipt_digest"]
        != _policy_candidate_authority_framed_digest(
            authority_contract.MIGRATION_RECEIPT_DIGEST_DOMAIN,
            receipt_json.encode("ascii"),
        )
        or row["signer_identity_digest"] != expected_signer_identity
        or row["signature_algorithm"] != "Ed25519"
        or row["detached_signature_digest"]
        != "sha256:" + hashlib.sha256(legacy_signature).hexdigest()
    ):
        raise PolicyCandidateAuthorityError(
            "completed-v9 legacy migration receipt is not recognized"
        )
    legacy_signing_digest = _policy_candidate_authority_framed_digest(
        authority_contract.MIGRATION_RECEIPT_SIGNATURE_DOMAIN,
        receipt_json.encode("ascii"),
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            legacy_signature,
            legacy_signing_digest.encode("ascii"),
        )
    except InvalidSignature as exc:
        raise PolicyCandidateAuthorityError(
            "completed-v9 legacy migration signature is invalid"
        ) from exc
    row.update(canonical_documents)
    row["receipt_json"] = receipt_json
    return row


def repair_policy_candidate_authority_completed_v9_receipt(
    *,
    migration_sha256: str,
    signer_public_key_base64url: str,
    detached_signature: str,
    source_schema_program: str,
    connection: Any,
) -> dict[str, Any]:
    if (
        not isinstance(connection, PostgresMetadataConnection)
        or connection.in_transaction
    ):
        raise PolicyCandidateAuthorityError(
            "completed-v9 repair requires an idle PostgreSQL bootstrap "
            "connection"
        )
    raw_connection = connection.raw_connection
    with raw_connection.transaction():
        connection.execute(
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
        )
        connection.execute(
            "SET LOCAL search_path TO "
            "serverware_metadata, pg_catalog, pg_temp"
        )
        connection.execute(
            "SELECT pg_catalog.pg_advisory_xact_lock(?)",
            (_POLICY_CANDIDATE_AUTHORITY_LOCK_KEY,),
        )
        if (
            _policy_candidate_authority_migration_version(connection)
            != _POLICY_CANDIDATE_AUTHORITY_SCHEMA_VERSION
        ):
            raise PolicyCandidateAuthorityError(
                "completed-v9 repair requires migration version 9"
            )
        (
            target_table_source,
            _legacy_schema_program,
            target_manifest,
            legacy_manifest,
        ) = _completed_v9_receipt_schema_programs(
            source_schema_program,
            connection=connection,
        )
        actual_manifest = _policy_candidate_authority_structure_manifest(
            connection
        )
        if actual_manifest == target_manifest:
            _validate_policy_candidate_authority_structure(
                connection,
                require_recorded_contract=True,
                source_schema_program=source_schema_program,
            )
            receipt = _policy_candidate_authority_offline_receipt(
                connection,
                source_version=8,
            )
            if (
                receipt is None
                or receipt["migration_sha256"] != migration_sha256
                or receipt["signer_public_key_base64url"]
                != signer_public_key_base64url
                or receipt["detached_signature"] != detached_signature
            ):
                raise PolicyCandidateAuthorityError(
                    "completed-v9 repair replay is not exact"
                )
            return {
                "contractId":
                    authority_contract.V8_TO_V9_MIGRATION_CONTRACT_ID,
                "receiptDigest": str(receipt["receipt_digest"]),
                "status": "completed",
                "exactReplay": True,
            }
        if actual_manifest != legacy_manifest:
            raise PolicyCandidateAuthorityError(
                "completed-v9 schema is neither the exact legacy shape nor "
                "the exact repair target"
            )
        legacy_manifest_json, legacy_manifest_digest = (
            _policy_candidate_authority_manifest_digest(legacy_manifest)
        )
        contract_rows = connection.execute(
            "SELECT schema_version, contract_id, source_revision, "
            "source_contract_digest, structural_manifest_json, "
            "structural_manifest_digest, offline_migration_receipt_digest "
            "FROM policy_authority_schema_contracts "
            "WHERE schema_version = ? LIMIT 2",
            (_POLICY_CANDIDATE_AUTHORITY_SCHEMA_VERSION,),
        ).fetchall()
        legacy_receipt = _completed_v9_legacy_receipt(
            connection,
            signer_public_key_base64url=signer_public_key_base64url,
        )
        expected_contract = {
            "schema_version": _POLICY_CANDIDATE_AUTHORITY_SCHEMA_VERSION,
            "contract_id": _POLICY_CANDIDATE_AUTHORITY_SCHEMA_CONTRACT,
            "source_revision": _POLICY_CANDIDATE_AUTHORITY_SOURCE_REVISION,
            "source_contract_digest":
                _policy_candidate_authority_source_contract_digest(),
            "structural_manifest_json": legacy_manifest_json,
            "structural_manifest_digest": legacy_manifest_digest,
            "offline_migration_receipt_digest":
                legacy_receipt["receipt_digest"],
        }
        if (
            len(contract_rows) != 1
            or any(
                contract_rows[0][field] != value
                for field, value in expected_contract.items()
            )
        ):
            raise PolicyCandidateAuthorityError(
                "completed-v9 legacy schema contract is not exact"
            )
        connection.execute(
            "DROP TABLE "
            + _policy_candidate_authority_identifier(
                _COMPLETED_V9_RECEIPT_TABLE
            )
        )
        _execute_metadata_schema_statements(
            connection,
            target_table_source,
        )
        recorded = record_policy_candidate_authority_v8_to_v9_receipt(
            migration_sha256=migration_sha256,
            before_manifest_json=legacy_receipt["before_manifest_json"],
            before_row_counts_json=legacy_receipt[
                "before_row_counts_json"
            ],
            after_manifest_json=legacy_receipt["after_manifest_json"],
            after_row_counts_json=legacy_receipt["after_row_counts_json"],
            signer_public_key_base64url=signer_public_key_base64url,
            detached_signature=detached_signature,
            completed_at=legacy_receipt["completed_at"],
            connection=connection,
        )
        _install_policy_candidate_authority_guards(connection)
        _seal_postgres_schema_acl(
            raw_connection,
            schema=_POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME,
            runtime_role=_METADATA_STORE_RUNTIME_ROLE,
            table_privileges=("SELECT", "INSERT", "UPDATE", "DELETE"),
            authority_executor_role=(
                _METADATA_STORE_AUTHORITY_EXECUTOR_ROLE
            ),
            authority_verifier_role=_METADATA_STORE_AUTHORITY_VERIFIER_ROLE,
            authority_verifier_read_tables=_POLICY_AUTHORITY_VERIFIER_READ_TABLES,
            authority_owner_role=_METADATA_STORE_AUTHORITY_OWNER_ROLE,
            authority_capability_issuer_role=(
                _METADATA_STORE_AUTHORITY_CAPABILITY_ISSUER_ROLE
            ),
            authority_planner_writer_role=(
                _METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE
            ),
            runtime_read_only_tables=(
                _POLICY_AUTHORITY_RUNTIME_READ_ONLY_TABLES
            ),
            authority_executor_function_signatures=(
                _POLICY_AUTHORITY_EXECUTOR_FUNCTION_SIGNATURES
            ),
            authority_capability_issuer_functions=(
                _POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTIONS
            ),
            authority_planner_writer_table_privileges=(
                _POLICY_AUTHORITY_PLANNER_WRITER_TABLE_PRIVILEGES
            ),
            authority_planner_writer_function_signatures=(
                AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES
            ),
        )
        repaired_manifest = _policy_candidate_authority_structure_manifest(
            connection
        )
        if repaired_manifest != target_manifest:
            raise PolicyCandidateAuthorityError(
                "completed-v9 repair did not produce the exact target shape"
            )
        target_manifest_json, target_manifest_digest = (
            _policy_candidate_authority_manifest_digest(target_manifest)
        )
        immutable_trigger = _policy_candidate_authority_object_name(
            "serverware",
            "policy_authority_schema_contracts",
            "immutable",
        )
        connection.execute(
            "DROP TRIGGER "
            + _policy_candidate_authority_identifier(immutable_trigger)
            + " ON policy_authority_schema_contracts"
        )
        updated = connection.execute(
            "UPDATE policy_authority_schema_contracts "
            "SET structural_manifest_json = ?, "
            "structural_manifest_digest = ?, "
            "offline_migration_receipt_digest = ? "
            "WHERE schema_version = ? AND contract_id = ? "
            "AND source_revision = ? AND source_contract_digest = ? "
            "AND structural_manifest_json = ? "
            "AND structural_manifest_digest = ? "
            "AND offline_migration_receipt_digest = ?",
            (
                target_manifest_json,
                target_manifest_digest,
                recorded["receiptDigest"],
                expected_contract["schema_version"],
                expected_contract["contract_id"],
                expected_contract["source_revision"],
                expected_contract["source_contract_digest"],
                expected_contract["structural_manifest_json"],
                expected_contract["structural_manifest_digest"],
                expected_contract["offline_migration_receipt_digest"],
            ),
        )
        if updated.rowcount != 1:
            raise PolicyCandidateAuthorityError(
                "completed-v9 schema contract repair CAS failed"
            )
        _install_policy_candidate_authority_guards(connection)
        _validate_policy_candidate_authority_structure(
            connection,
            require_recorded_contract=True,
            source_schema_program=source_schema_program,
        )
        final_receipt = _policy_candidate_authority_offline_receipt(
            connection,
            source_version=8,
        )
        if (
            final_receipt is None
            or final_receipt["receipt_digest"]
            != recorded["receiptDigest"]
        ):
            raise PolicyCandidateAuthorityError(
                "completed-v9 repaired receipt is not exact"
            )
        return {
            "contractId":
                authority_contract.V8_TO_V9_MIGRATION_CONTRACT_ID,
            "receiptDigest": str(recorded["receiptDigest"]),
            "status": "completed",
            "exactReplay": False,
        }


for _compatibility_name in _EXTRACTED_NAMES:
    _compatibility_export = globals().get(_compatibility_name)
    if callable(_compatibility_export) and _compatibility_name != "bind_db_globals":
        _compatibility_export.__module__ = "serverware.db"
del _compatibility_export
del _compatibility_name
