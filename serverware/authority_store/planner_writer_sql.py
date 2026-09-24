"""Source-owned planner-writer metadata privileges, without database IO.

One fixed catalog query is used by sealing and configured v4 writer connection
admission. A returned violation denies; no row means only this namespace's
privilege and function-metadata contract matched. It is not TLS/session/
transaction admission, function-body verification, root currentness, or
authorization to execute a plan. Callers supply only role and namespace names,
never a grant inventory.
"""
from __future__ import annotations

import hashlib
from types import MappingProxyType


PLANNER_WRITER_TABLE_PRIVILEGES = MappingProxyType({
    "policy_authority_authorization_dependency_manifests": frozenset({"SELECT"}),
    "policy_authority_authorization_projections": frozenset({"SELECT", "INSERT"}),
    "policy_authority_execution_envelopes": frozenset({"SELECT", "INSERT", "UPDATE"}),
    "policy_authority_fence_heads": frozenset({"SELECT"}),
    "policy_authority_operation_mutation_templates": frozenset({"SELECT"}),
    "policy_authority_planner_transactions": frozenset({"SELECT", "INSERT", "UPDATE"}),
    "policy_authority_revocation_retained_plans": frozenset({"SELECT", "INSERT"}),
    "policy_authority_revocation_writer_requests": frozenset({"SELECT", "INSERT"}),
    "policy_authority_revocation_writer_acknowledgments": frozenset({"SELECT", "INSERT"}),
    "policy_authority_query_dependency_manifests": frozenset({"SELECT"}),
    "policy_authority_authenticated_table_roots": frozenset({"SELECT"}),
    "policy_authority_webauthn_assertion_evidence": frozenset({"SELECT", "INSERT"}),
    "policy_authority_writer_capabilities": frozenset({"SELECT", "UPDATE"}),
})
AUDIT_CAPACITY_FUNCTION_NAME = "serverware_policy_authority_assert_audit_capacity"
PLANNER_WRITER_FUNCTION_SIGNATURES = (
    (AUDIT_CAPACITY_FUNCTION_NAME, ("text", "jsonb", "jsonb", "bigint")),
    ("serverware_policy_authority_domain_digest", ("text", "text[]")),
    ("serverware_policy_authority_wire_json", ("jsonb",)),
    ("serverware_policy_authority_wire_string", ("text", "boolean", "bigint")),
    ("serverware_policy_authority_wire_walk", ("jsonb", "integer", "bigint", "bigint", "boolean")),
)
PLANNER_WRITER_FUNCTION_CONTRACTS = MappingProxyType({
    name: MappingProxyType({
        "argumentTypes": arguments,
        "securityDefiner": False,
        "strict": name != AUDIT_CAPACITY_FUNCTION_NAME,
        "volatility": "v" if name == AUDIT_CAPACITY_FUNCTION_NAME else "i",
        "language": "plpgsql",
        "searchPath": ("pg_catalog",) if name.startswith("serverware_policy_authority_wire_")
            else ("pg_catalog", "$metadata", "pg_temp"),
    }) for name, arguments in PLANNER_WRITER_FUNCTION_SIGNATURES
})


def _literal(value):
    # Only the immutable source inventories below enter SQL text.
    return "'" + value.replace("'", "''") + "'"


_TABLE_VALUES = ",\n        ".join(
    "(" + _literal(name) + ", ARRAY["
    + ", ".join(_literal(privilege) for privilege in sorted(privileges))
    + "]::pg_catalog.text[])"
    for name, privileges in sorted(PLANNER_WRITER_TABLE_PRIVILEGES.items())
)
_FUNCTION_VALUES = ",\n        ".join(
    "(" + _literal(name) + ", " + _literal(", ".join(contract["argumentTypes"]))
    + ", " + ("TRUE" if contract["strict"] else "FALSE")
    + ", " + _literal(contract["volatility"])
    + ", " + ("TRUE" if contract["searchPath"] == ("pg_catalog",) else "FALSE") + ")"
    for name, contract in sorted(PLANNER_WRITER_FUNCTION_CONTRACTS.items())
)

PLANNER_WRITER_PRIVILEGE_SQL = """WITH requested AS (
    SELECT %s::pg_catalog.text AS role_name,
           %s::pg_catalog.text AS namespace_name
), expected_tables(table_name, privileges) AS (
    VALUES """ + _TABLE_VALUES + """
), expected_functions(function_name, argument_types, strict, volatility, catalog_only) AS (
    VALUES """ + _FUNCTION_VALUES + """
), authority AS (
    SELECT requested.*, role_record.oid AS role_oid,
           role_record.rolcanlogin, role_record.rolsuper,
           role_record.rolcreaterole, role_record.rolcreatedb,
           role_record.rolreplication, role_record.rolbypassrls,
           namespace.oid AS namespace_oid, namespace.nspowner,
           namespace.nspacl
    FROM requested
    LEFT JOIN pg_catalog.pg_roles AS role_record
      ON role_record.rolname = requested.role_name
    LEFT JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.nspname = requested.namespace_name
), metadata_relations AS (
    SELECT relation.oid, relation.relname, relation.relkind,
           relation.relowner, relation.relacl, authority.role_oid,
           authority.nspowner, expected_tables.privileges
    FROM authority
    JOIN pg_catalog.pg_class AS relation
      ON relation.relnamespace = authority.namespace_oid
    LEFT JOIN expected_tables
      ON expected_tables.table_name = relation.relname::pg_catalog.text
), metadata_functions AS (
    SELECT function_record.oid, function_record.proowner,
           function_record.proacl, function_record.prokind,
           function_record.prosecdef, function_record.proisstrict,
           function_record.provolatile, function_record.proconfig,
           language.lanname, authority.role_oid, authority.nspowner,
           authority.namespace_name, expected_functions.function_name,
           expected_functions.strict, expected_functions.volatility,
           expected_functions.catalog_only
    FROM authority
    JOIN pg_catalog.pg_proc AS function_record
      ON function_record.pronamespace = authority.namespace_oid
    LEFT JOIN pg_catalog.pg_language AS language
      ON language.oid = function_record.prolang
    LEFT JOIN expected_functions
      ON expected_functions.function_name = function_record.proname::pg_catalog.text
     AND expected_functions.argument_types = pg_catalog.oidvectortypes(function_record.proargtypes)
), violations AS (
    SELECT 'role-or-namespace'::pg_catalog.text AS violation
    FROM authority
    WHERE role_oid IS NULL OR namespace_oid IS NULL
       OR rolcanlogin IS NOT TRUE
       OR rolsuper IS NOT FALSE OR rolcreaterole IS NOT FALSE
       OR rolcreatedb IS NOT FALSE OR rolreplication IS NOT FALSE
       OR rolbypassrls IS NOT FALSE
    UNION ALL
    SELECT 'schema-or-database-privilege'
    FROM authority
    WHERE CASE WHEN role_oid IS NOT NULL AND namespace_oid IS NOT NULL THEN
        pg_catalog.has_schema_privilege(role_oid, namespace_oid, 'USAGE') IS NOT TRUE
        OR pg_catalog.has_schema_privilege(role_oid, namespace_oid, 'CREATE') IS NOT FALSE
        OR pg_catalog.has_schema_privilege(role_oid, namespace_oid,
            'USAGE WITH GRANT OPTION,CREATE WITH GRANT OPTION') IS NOT FALSE
        OR pg_catalog.has_database_privilege(role_oid, pg_catalog.current_database(),
            'CREATE,TEMPORARY') IS NOT FALSE
        ELSE TRUE END
    UNION ALL
    SELECT 'role-membership'
    FROM authority
    JOIN pg_catalog.pg_auth_members AS membership
      ON membership.member = authority.role_oid OR membership.roleid = authority.role_oid
    UNION ALL
    SELECT 'required-table'
    FROM authority CROSS JOIN expected_tables
    LEFT JOIN pg_catalog.pg_class AS relation
      ON relation.relnamespace = authority.namespace_oid
     AND relation.relname::pg_catalog.text = expected_tables.table_name
    WHERE relation.oid IS NULL OR relation.relkind NOT IN ('r', 'p')
       OR relation.relowner IS DISTINCT FROM authority.nspowner
    UNION ALL
    SELECT 'table-privilege'
    FROM metadata_relations
    CROSS JOIN LATERAL pg_catalog.unnest(ARRAY[
        'SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'
    ]::pg_catalog.text[]) AS requested_privilege(privilege)
    WHERE CASE WHEN relkind IN ('r', 'p', 'v', 'm', 'f') THEN
        pg_catalog.has_table_privilege(role_oid, oid, privilege) IS DISTINCT FROM
            (relkind IN ('r', 'p') AND privilege = ANY(COALESCE(privileges, ARRAY[]::pg_catalog.text[])))
        OR pg_catalog.has_table_privilege(role_oid, oid, privilege || ' WITH GRANT OPTION') IS NOT FALSE
        ELSE FALSE END
    UNION ALL
    SELECT 'column-privilege'
    FROM metadata_relations
    JOIN pg_catalog.pg_attribute AS attribute
      ON attribute.attrelid = metadata_relations.oid
     AND attribute.attnum > 0 AND attribute.attisdropped IS FALSE
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        CASE WHEN relkind IN ('r', 'p', 'v', 'm', 'f') THEN
            COALESCE(attribute.attacl, ARRAY[]::pg_catalog.aclitem[])
        ELSE ARRAY[]::pg_catalog.aclitem[] END
    ) AS grant_entry
    WHERE grant_entry.grantee = role_oid OR grant_entry.grantee = 0
    UNION ALL
    SELECT 'sequence-privilege'
    FROM metadata_relations
    WHERE CASE WHEN relkind = 'S' THEN
        pg_catalog.has_sequence_privilege(role_oid, oid, 'SELECT,USAGE,UPDATE') IS NOT FALSE
        OR pg_catalog.has_sequence_privilege(role_oid, oid,
            'SELECT WITH GRANT OPTION,USAGE WITH GRANT OPTION,UPDATE WITH GRANT OPTION') IS NOT FALSE
        ELSE FALSE END
    UNION ALL
    SELECT 'required-function'
    FROM authority CROSS JOIN expected_functions
    LEFT JOIN pg_catalog.pg_proc AS function_record
      ON function_record.pronamespace = authority.namespace_oid
     AND function_record.proname::pg_catalog.text = expected_functions.function_name
     AND pg_catalog.oidvectortypes(function_record.proargtypes) = expected_functions.argument_types
    WHERE function_record.oid IS NULL OR function_record.prokind IS DISTINCT FROM 'f'
    UNION ALL
    SELECT 'function-privilege'
    FROM metadata_functions
    WHERE pg_catalog.has_function_privilege(role_oid, oid, 'EXECUTE') IS DISTINCT FROM
            (function_name IS NOT NULL)
       OR pg_catalog.has_function_privilege(role_oid, oid, 'EXECUTE WITH GRANT OPTION') IS NOT FALSE
    UNION ALL
    SELECT 'function-metadata'
    FROM metadata_functions
    WHERE function_name IS NOT NULL AND (
        prokind IS DISTINCT FROM 'f' OR proowner IS DISTINCT FROM nspowner
        OR prosecdef IS NOT FALSE OR proisstrict IS DISTINCT FROM strict
        OR provolatile::pg_catalog.text IS DISTINCT FROM volatility
        OR lanname::pg_catalog.text IS DISTINCT FROM 'plpgsql'
        OR proconfig IS DISTINCT FROM CASE WHEN catalog_only THEN
            ARRAY['search_path=pg_catalog']::pg_catalog.text[]
            ELSE ARRAY['search_path=pg_catalog, ' || pg_catalog.quote_ident(namespace_name)
                || ', pg_temp']::pg_catalog.text[] END
    )
    UNION ALL
    SELECT 'public-schema-privilege'
    FROM authority
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
        nspacl, pg_catalog.acldefault('n'::pg_catalog."char", nspowner)
    )) AS grant_entry
    WHERE grant_entry.grantee = 0
    UNION ALL
    SELECT 'public-relation-privilege'
    FROM metadata_relations
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        CASE WHEN relkind IN ('r', 'p', 'v', 'm', 'f', 'S') THEN
            COALESCE(relacl, pg_catalog.acldefault(
                CASE WHEN relkind = 'S' THEN 'S'::pg_catalog."char"
                     ELSE 'r'::pg_catalog."char" END, relowner))
        ELSE ARRAY[]::pg_catalog.aclitem[] END
    ) AS grant_entry
    WHERE grant_entry.grantee = 0
    UNION ALL
    SELECT 'public-function-privilege'
    FROM metadata_functions
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
        proacl, pg_catalog.acldefault('f'::pg_catalog."char", proowner)
    )) AS grant_entry
    WHERE grant_entry.grantee = 0
)
SELECT violation FROM violations LIMIT 1"""

PLANNER_WRITER_PRIVILEGE_SQL_DIGEST = (
    "sha256:" + hashlib.sha256(PLANNER_WRITER_PRIVILEGE_SQL.encode("utf-8")).hexdigest()
)


def planner_writer_privilege_check(*, role: str, namespace: str) -> tuple[str, tuple[str, str]]:
    """Return the fixed source query and only its two bounded name values."""
    for label, value in (("role", role), ("namespace", namespace)):
        if type(value) is not str or not 1 <= len(value) <= 63 or "\x00" in value:
            raise ValueError(f"planner writer {label} is not a bounded name")
        try:
            if len(value.encode("utf-8")) > 63:
                raise ValueError(f"planner writer {label} is not a bounded name")
        except UnicodeError as exc:
            raise ValueError(f"planner writer {label} is not a bounded name") from exc
    return PLANNER_WRITER_PRIVILEGE_SQL, (role, namespace)
