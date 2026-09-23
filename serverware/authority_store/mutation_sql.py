"""Shared v9 locked-row/CAS SQL, without database or registry imports.

These fragments execute only after the caller's manifest, digest, selected-set,
and capability admission. They do not authenticate a row, root, or predicate.
The live executor embeds their exact text in its installed function definition;
existing databases still need the separately authorized function repair, not an
automatic reinstall. The component fixture executes these same fragments.
"""
from __future__ import annotations

import re
import textwrap


_RECORD_FIELDS = {
    "authorization_source": ("present", "row", "rowDigest", "selector", "table"),
    "mutation": ("expectedRow", "key", "keyDigest", "operation", "row", "table", "templateId"),
}
_SELECTORS = {
    "authorization_source": "selector",
    "selected_row": "key",
    "mutation": "key",
}


def _schema_name(namespace: str) -> str:
    if not isinstance(namespace, str) or re.fullmatch(
        r'"[a-z][a-z0-9_]{0,127}"', namespace
    ) is None:
        raise ValueError("mutation namespace must be an exact quoted identifier")
    # The installer supplies an SQL identifier, but catalog names and format
    # %I parameters are *unquoted* names. Never strip arbitrary caller text.
    return namespace[1:-1]


def closed_record_sql(record: str) -> str:
    """Return a definite boolean for the two closed wire-object key sets."""
    if record not in _RECORD_FIELDS:
        raise ValueError("unsupported closed mutation record")
    fields = ", ".join("'" + field + "'" for field in _RECORD_FIELDS[record])
    return textwrap.dedent(f"""
        (CASE WHEN pg_catalog.jsonb_typeof({record}) IS DISTINCT FROM 'object'
            THEN FALSE
            ELSE (
                SELECT pg_catalog.array_agg(field ORDER BY field COLLATE "C")
                FROM pg_catalog.jsonb_object_keys({record}) AS field
            ) IS NOT DISTINCT FROM ARRAY[{fields}]::text[]
        END)
    """).strip()


def selected_row_matches_sql(record: str) -> str:
    """Distinguish SQL absence, explicit JSON null, and exact object presence.

    Missing fields and stringified booleans never stand for absence. The current
    row is the caller's locked, full to_jsonb(target) projection.
    """
    if record not in ("authorization_source", "selected_row"):
        raise ValueError("unsupported selected row record")
    return textwrap.dedent(f"""
        (CASE
            WHEN {record}->'present' = 'true'::pg_catalog.jsonb THEN
                current_row IS NOT NULL
                AND pg_catalog.jsonb_typeof({record}->'row')
                    IS NOT DISTINCT FROM 'object'
                AND current_row IS NOT DISTINCT FROM {record}->'row'
            WHEN {record}->'present' = 'false'::pg_catalog.jsonb THEN
                current_row IS NULL
                AND {record}->'row' IS NOT DISTINCT FROM 'null'::pg_catalog.jsonb
            ELSE FALSE
        END)
    """).strip()


def locked_primary_key_row_sql(namespace: str, record: str) -> str:
    """Assign key_predicate/current_row from admitted key_columns and record.

    The caller declares key_columns/current_row jsonb, key_predicate text,
    key_names/supplied_key_names text[] and matched_count bigint. Existing caller
    key-name closure is retained; this fragment additionally requires every named
    column to resolve, so it cannot accidentally construct a partial predicate.
    Every dynamic statement receives the full record as $1, never only its row.
    """
    schema = _schema_name(namespace)
    if record not in _SELECTORS:
        raise ValueError("unsupported locked row record")
    selector = _SELECTORS[record]
    return textwrap.dedent(f"""
        IF pg_catalog.jsonb_typeof(key_columns) IS DISTINCT FROM 'array'
            OR pg_catalog.jsonb_typeof({record}->'{selector}') IS DISTINCT FROM 'object'
            OR pg_catalog.jsonb_typeof({record}->'table') IS DISTINCT FROM 'string'
        THEN
            RAISE EXCEPTION 'authority v9 primary key selector is invalid';
        END IF;
        IF pg_catalog.jsonb_array_length(key_columns) = 0
            OR EXISTS (
                SELECT 1 FROM pg_catalog.jsonb_array_elements(key_columns) AS item(value)
                WHERE pg_catalog.jsonb_typeof(item.value) IS DISTINCT FROM 'string'
            )
        THEN
            RAISE EXCEPTION 'authority v9 primary key columns are invalid';
        END IF;
        SELECT pg_catalog.array_agg(value ORDER BY value COLLATE "C")
        INTO key_names FROM pg_catalog.jsonb_array_elements_text(key_columns);
        SELECT pg_catalog.array_agg(key ORDER BY key COLLATE "C")
        INTO supplied_key_names FROM pg_catalog.jsonb_object_keys({record}->'{selector}') AS key;
        IF key_names IS DISTINCT FROM supplied_key_names THEN
            RAISE EXCEPTION 'authority v9 primary key selector is not exact';
        END IF;
        SELECT pg_catalog.string_agg(
            pg_catalog.format(
                'target.%I IS NOT DISTINCT FROM '
                '(($1->''{selector}''->>%L)::%s)',
                key_column.column_name,
                key_column.column_name,
                pg_catalog.format_type(attribute.atttypid, attribute.atttypmod)
            ),
            ' AND ' ORDER BY key_column.ordinal
        ), pg_catalog.count(*)
        INTO key_predicate, matched_count
        FROM pg_catalog.jsonb_array_elements_text(key_columns)
            WITH ORDINALITY AS key_column(column_name, ordinal)
        JOIN pg_catalog.pg_class AS relation
            ON relation.relname = {record}->>'table'
        JOIN pg_catalog.pg_namespace AS relation_namespace
            ON relation_namespace.oid = relation.relnamespace
            AND relation_namespace.nspname = '{schema}'
        JOIN pg_catalog.pg_attribute AS attribute
            ON attribute.attrelid = relation.oid
            AND attribute.attname = key_column.column_name
            AND attribute.attnum > 0
            AND NOT attribute.attisdropped;
        IF key_predicate IS NULL
            OR matched_count <> pg_catalog.jsonb_array_length(key_columns)
        THEN
            RAISE EXCEPTION 'authority v9 primary key catalog columns are not exact';
        END IF;
        EXECUTE pg_catalog.format(
            'SELECT to_jsonb(target) FROM %I.%I AS target '
            'WHERE %s FOR UPDATE',
            '{schema}', {record}->>'table', key_predicate
        )
        INTO current_row
        USING {record};
    """)


def apply_mutation_sql(namespace: str) -> str:
    """Apply one already-admitted mutation, retaining exact CAS/cardinality.

    The caller declares key_columns/current_row/post_row jsonb,
    key_names/supplied_key_names text[], key_predicate/update_columns text and
    matched_count bigint. INSERT alone maps explicit JSON-null expectedRow to
    SQL row absence; no missing-field fallback. The original key drives the
    lock, DML and postcondition, rejecting key moves.
    """
    schema = _schema_name(namespace)
    return textwrap.dedent(f"""
        {locked_primary_key_row_sql(namespace, 'mutation')}
        IF mutation->>'operation' = 'INSERT' THEN
            IF current_row IS NOT NULL
                OR mutation->'expectedRow' IS DISTINCT FROM 'null'::pg_catalog.jsonb
            THEN
                RAISE EXCEPTION 'authority v9 mutation CAS precondition changed';
            END IF;
        ELSIF mutation->>'operation' IN ('UPDATE', 'DELETE') THEN
            IF current_row IS NULL
                OR pg_catalog.jsonb_typeof(mutation->'expectedRow')
                    IS DISTINCT FROM 'object'
                OR current_row IS DISTINCT FROM mutation->'expectedRow'
            THEN
                RAISE EXCEPTION 'authority v9 mutation CAS precondition changed';
            END IF;
        ELSE
            RAISE EXCEPTION 'authority v9 mutation template is unreachable';
        END IF;

        IF mutation->>'operation' IN ('INSERT', 'UPDATE') THEN
            IF pg_catalog.jsonb_typeof(mutation->'row') IS DISTINCT FROM 'object' THEN
                RAISE EXCEPTION 'authority v9 mutation row image is invalid';
            END IF;
            SELECT pg_catalog.string_agg(
                pg_catalog.format('%I', attribute.attname),
                ', ' ORDER BY attribute.attnum
            )
            INTO update_columns
            FROM pg_catalog.pg_attribute AS attribute
            JOIN pg_catalog.pg_class AS relation ON relation.oid = attribute.attrelid
            JOIN pg_catalog.pg_namespace AS relation_namespace
                ON relation_namespace.oid = relation.relnamespace
            WHERE relation_namespace.nspname = '{schema}'
              AND relation.relname = mutation->>'table'
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
              AND attribute.attgenerated = ''
              AND attribute.attidentity = '';
            IF update_columns IS NULL THEN
                RAISE EXCEPTION 'authority v9 mutation has no writable columns';
            END IF;
            IF mutation->>'operation' = 'INSERT' THEN
                EXECUTE pg_catalog.format(
                    'INSERT INTO %I.%I (%s) SELECT %s FROM '
                    'pg_catalog.jsonb_populate_record(NULL::%I.%I, $1->''row'')',
                    '{schema}', mutation->>'table', update_columns, update_columns,
                    '{schema}', mutation->>'table'
                ) USING mutation;
            ELSE
                EXECUTE pg_catalog.format(
                    'UPDATE %I.%I AS target SET (%s) = (SELECT %s FROM '
                    'pg_catalog.jsonb_populate_record(NULL::%I.%I, $1->''row'')) '
                    'WHERE %s',
                    '{schema}', mutation->>'table', update_columns, update_columns,
                    '{schema}', mutation->>'table', key_predicate
                ) USING mutation;
            END IF;
        ELSE
            IF mutation->'row' IS DISTINCT FROM 'null'::pg_catalog.jsonb THEN
                RAISE EXCEPTION 'authority v9 delete precondition is invalid';
            END IF;
            EXECUTE pg_catalog.format(
                'DELETE FROM %I.%I AS target WHERE %s',
                '{schema}', mutation->>'table', key_predicate
            ) USING mutation;
        END IF;
        GET DIAGNOSTICS matched_count = ROW_COUNT;
        IF matched_count <> 1 THEN
            RAISE EXCEPTION 'authority v9 mutation cardinality is not exact';
        END IF;
        EXECUTE pg_catalog.format(
            'SELECT to_jsonb(target) FROM %I.%I AS target WHERE %s',
            '{schema}', mutation->>'table', key_predicate
        ) INTO post_row USING mutation;
        IF (mutation->>'operation' = 'DELETE' AND post_row IS NOT NULL)
            OR (mutation->>'operation' <> 'DELETE'
                AND post_row IS DISTINCT FROM mutation->'row')
        THEN
            RAISE EXCEPTION 'authority v9 mutation postcondition changed';
        END IF;
    """)
