"""Source-owned verifier read-role admission, without database or registry IO.

The caller executes this fixed catalog query before business reads (or after
sealing grants). No returned row means the role has the exact current metadata
read surface; any row denies admission. This is privilege evidence only, not
authentication of database contents, root currentness, or installed services.
"""
from __future__ import annotations

import hashlib

from serverware import authority_contract


VERIFIER_READ_PRIVILEGE_SQL = """WITH requested AS (
    SELECT %s::pg_catalog.text AS role_name,
           %s::pg_catalog.text AS namespace_name,
           %s::pg_catalog.text[] AS required_tables
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
           relation.relowner, relation.relacl,
           authority.role_oid, authority.required_tables
    FROM authority
    JOIN pg_catalog.pg_class AS relation
      ON relation.relnamespace = authority.namespace_oid
), metadata_functions AS (
    SELECT function_record.oid, function_record.proowner,
           function_record.proacl, authority.role_oid
    FROM authority
    JOIN pg_catalog.pg_proc AS function_record
      ON function_record.pronamespace = authority.namespace_oid
), violations AS (
    SELECT 'role-or-namespace'::pg_catalog.text AS violation
    FROM authority
    WHERE role_oid IS NULL OR namespace_oid IS NULL
       OR rolcanlogin IS NOT TRUE
       OR rolsuper IS NOT FALSE
       OR rolcreaterole IS NOT FALSE
       OR rolcreatedb IS NOT FALSE
       OR rolreplication IS NOT FALSE
       OR rolbypassrls IS NOT FALSE
    UNION ALL
    SELECT 'schema-or-database-privilege'
    FROM authority
    WHERE CASE WHEN role_oid IS NOT NULL AND namespace_oid IS NOT NULL THEN
        pg_catalog.has_schema_privilege(
            role_oid, namespace_oid, 'USAGE') IS NOT TRUE
        OR pg_catalog.has_schema_privilege(
            role_oid, namespace_oid, 'CREATE') IS NOT FALSE
        OR pg_catalog.has_schema_privilege(
            role_oid, namespace_oid,
            'USAGE WITH GRANT OPTION,CREATE WITH GRANT OPTION') IS NOT FALSE
        OR pg_catalog.has_database_privilege(
            role_oid, pg_catalog.current_database(),
            'CREATE,TEMPORARY') IS NOT FALSE
        ELSE TRUE END
    UNION ALL
    SELECT 'role-membership'
    FROM authority
    JOIN pg_catalog.pg_auth_members AS membership
      ON membership.member = authority.role_oid
      OR membership.roleid = authority.role_oid
    UNION ALL
    SELECT 'required-table-select'
    FROM authority
    CROSS JOIN LATERAL pg_catalog.unnest(authority.required_tables)
        AS expected(table_name)
    LEFT JOIN pg_catalog.pg_class AS relation
      ON relation.relnamespace = authority.namespace_oid
     AND relation.relname = expected.table_name
    WHERE CASE WHEN relation.oid IS NOT NULL
                    AND relation.relkind IN ('r', 'p') THEN
        pg_catalog.has_table_privilege(
            authority.role_oid, relation.oid, 'SELECT') IS NOT TRUE
        ELSE TRUE END
    UNION ALL
    SELECT 'table-or-column-privilege'
    FROM metadata_relations
    WHERE CASE WHEN relkind IN ('r', 'p', 'v', 'm', 'f') THEN
        pg_catalog.has_table_privilege(
            role_oid, oid,
            'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') IS NOT FALSE
        OR pg_catalog.has_any_column_privilege(
            role_oid, oid, 'INSERT,UPDATE,REFERENCES') IS NOT FALSE
        OR pg_catalog.has_table_privilege(
            role_oid, oid,
            'SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,'
            'UPDATE WITH GRANT OPTION,DELETE WITH GRANT OPTION,'
            'TRUNCATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION,'
            'TRIGGER WITH GRANT OPTION') IS NOT FALSE
        OR pg_catalog.has_any_column_privilege(
            role_oid, oid,
            'SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,'
            'UPDATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION') IS NOT FALSE
        OR (relname::pg_catalog.text = ANY(required_tables)) IS NOT TRUE
           AND (
               pg_catalog.has_table_privilege(
                   role_oid, oid, 'SELECT') IS NOT FALSE
               OR pg_catalog.has_any_column_privilege(
                   role_oid, oid, 'SELECT') IS NOT FALSE
           )
        ELSE FALSE END
    UNION ALL
    SELECT 'sequence-privilege'
    FROM metadata_relations
    WHERE CASE WHEN relkind = 'S' THEN
        pg_catalog.has_sequence_privilege(
            role_oid, oid, 'SELECT,USAGE,UPDATE') IS NOT FALSE
        ELSE FALSE END
    UNION ALL
    SELECT 'function-privilege'
    FROM metadata_functions
    WHERE pg_catalog.has_function_privilege(
        role_oid, oid, 'EXECUTE') IS NOT FALSE
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
        ELSE NULL::pg_catalog.aclitem[] END
    ) AS grant_entry
    WHERE grant_entry.grantee = 0
    UNION ALL
    SELECT 'public-column-privilege'
    FROM metadata_relations
    JOIN pg_catalog.pg_attribute AS attribute
      ON attribute.attrelid = metadata_relations.oid
     AND attribute.attnum > 0
     AND attribute.attisdropped IS FALSE
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        CASE WHEN relkind IN ('r', 'p', 'v', 'm', 'f') THEN
            attribute.attacl
        ELSE NULL::pg_catalog.aclitem[] END
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

VERIFIER_READ_PRIVILEGE_SQL_DIGEST = (
    "sha256:"
    + hashlib.sha256(VERIFIER_READ_PRIVILEGE_SQL.encode("utf-8")).hexdigest()
)


def verifier_read_privilege_check(
    *, role: str, namespace: str
) -> tuple[str, tuple[str, str, list[str]]]:
    """Return only the fixed query and its three bound, source-closed inputs."""
    for label, value in (("role", role), ("namespace", namespace)):
        if (
            type(value) is not str
            or not value
            or len(value) > 63
            or "\x00" in value
        ):
            raise ValueError(f"verifier read {label} is not a bounded name")
        try:
            encoded = value.encode("utf-8")
        except UnicodeError as exc:
            raise ValueError(
                f"verifier read {label} is not a bounded name"
            ) from exc
        if len(encoded) > 63:
            raise ValueError(f"verifier read {label} is not a bounded name")
    return (
        VERIFIER_READ_PRIVILEGE_SQL,
        (role, namespace, sorted(authority_contract.VERIFIER_READ_TABLES)),
    )
