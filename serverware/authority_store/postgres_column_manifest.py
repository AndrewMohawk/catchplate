"""PostgreSQL 16 column metadata independent of business-table privileges.

The source structure manifest must describe the same catalog for the installer
and restricted readers. information_schema.columns intentionally filters by
ownership/column privileges; using that view makes an otherwise correct
restricted reader omit source columns. This query reads public system metadata
only. It does not grant relation access, inspect business rows or switch roles.

The six existing manifest values preserve PostgreSQL 16's column projection:
domains use the underlying type name, arrays have the ARRAY label, noncatalog
types use USER-DEFINED, domain NOT NULL contributes to nullability, and generated
columns do not acquire an ordinary default. Identifier/ordinal ordering is
unchanged. Expected-schema generation and runtime observation share this query.

Reference: PostgreSQL REL_16_STABLE, src/backend/catalog/information_schema.sql,
the columns view. Behavioral agreement still requires frozen PostgreSQL tests.
"""
from __future__ import annotations


COLUMN_MANIFEST_SQL = """
SELECT
    attribute.attname AS column_name,
    CASE
        WHEN resolved_type.typelem <> 0 AND resolved_type.typlen = -1
            THEN 'ARRAY'
        WHEN type_namespace.nspname = 'pg_catalog'
            THEN pg_catalog.format_type(resolved_type.oid, NULL)
        ELSE 'USER-DEFINED'
    END AS data_type,
    resolved_type.typname AS udt_name,
    CASE
        WHEN attribute.attnotnull
            OR (declared_type.typtype = 'd' AND declared_type.typnotnull)
            THEN 'NO'
        ELSE 'YES'
    END AS is_nullable,
    CASE
        WHEN attribute.attgenerated = ''
            THEN pg_catalog.pg_get_expr(default_record.adbin, default_record.adrelid)
        ELSE NULL
    END AS column_default,
    attribute.attnum AS ordinal_position
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = relation.relnamespace
JOIN pg_catalog.pg_attribute AS attribute
    ON attribute.attrelid = relation.oid
JOIN pg_catalog.pg_type AS declared_type
    ON declared_type.oid = attribute.atttypid
JOIN pg_catalog.pg_type AS resolved_type
    ON resolved_type.oid = CASE
        WHEN declared_type.typtype = 'd' THEN declared_type.typbasetype
        ELSE declared_type.oid
    END
JOIN pg_catalog.pg_namespace AS type_namespace
    ON type_namespace.oid = resolved_type.typnamespace
LEFT JOIN pg_catalog.pg_attrdef AS default_record
    ON default_record.adrelid = relation.oid
    AND default_record.adnum = attribute.attnum
WHERE namespace.nspname = ? AND relation.relname = ?
    AND relation.relkind IN ('r', 'p')
    AND attribute.attnum > 0 AND NOT attribute.attisdropped
    AND NOT pg_catalog.pg_is_other_temp_schema(namespace.oid)
ORDER BY attribute.attnum
"""
