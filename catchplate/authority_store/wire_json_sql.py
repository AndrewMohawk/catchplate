"""Install a separate bounded ASCII wire serializer; never change tree JSON.

The public entry measures/validates the entire value before rendering. Bounds
cover visited values/keys, nesting and emitted ASCII bytes, not PostgreSQL's
prior JSONB parse/detoast, SRF/sort allocations, total process RSS or runtime.
JSONB has already discarded duplicate keys and original numeric token spelling;
this serializer cannot replace raw-byte/duplicate/integer admission checks.

Reference semantics: CPython Modules/_json.c ascii_escape_unicode (including
DEL escaping), Python json.JSONEncoder, and PostgreSQL 16/17 JSON Types. JSONB
preserves fractional scale but normalizes exponents: 1.0 is refused, while an
already normalized JSONB 1e2 is indistinguishable from integer 100.
"""
from __future__ import annotations

import textwrap

from catchplate.authority_store.mutation_sql import _schema_name


WIRE_JSON_MAX_DEPTH = 128
WIRE_JSON_MAX_NODES = 1_000_000
WIRE_JSON_MAX_BYTES = 72 * 1024 * 1024
WIRE_JSON_FUNCTION_NAMES = (
    "catchplate_policy_authority_wire_string",
    "catchplate_policy_authority_wire_walk",
    "catchplate_policy_authority_wire_json",
)


def wire_json_function_sql(namespace: str) -> str:
    """Return only the three fixed, owner-installed function declarations.

The installer's existing owner/execute closure must revoke PUBLIC and pin all
three names. No grants, table access or old canonical_json replacement occurs.
"""
    _schema_name(namespace)
    return textwrap.dedent(f"""
        CREATE OR REPLACE FUNCTION {namespace}.catchplate_policy_authority_wire_string(
            input_value text, render_value boolean, maximum_bytes bigint
        ) RETURNS TABLE(rendered text, emitted_bytes bigint)
        LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER
        SET search_path = pg_catalog
        AS $catchplate_wire_string$
        DECLARE
            encoded bytea;
            input_bytes integer;
            position integer := 0;
            first_byte integer;
            codepoint integer;
            width integer;
            fragment text;
            chunk text := '';
            parts text[] := ARRAY[]::text[];
            slash constant text := pg_catalog.chr(92);
        BEGIN
            IF maximum_bytes NOT BETWEEN 1 AND {WIRE_JSON_MAX_BYTES} THEN
                RAISE EXCEPTION 'authority wire JSON byte budget is invalid';
            END IF;
            emitted_bytes := 2;
            IF pg_catalog.octet_length(input_value)::bigint + 2 > maximum_bytes THEN
                RAISE EXCEPTION 'authority wire JSON byte bound exceeded';
            END IF;
            -- Plain printable ASCII needs no per-character escaping. DEL is
            -- deliberately outside this range, just as in CPython S_CHAR.
            IF input_value COLLATE "C" !~ '[^ -~]'
                AND pg_catalog.strpos(input_value, '"') = 0
                AND pg_catalog.strpos(input_value, slash) = 0
            THEN
                emitted_bytes := pg_catalog.octet_length(input_value)::bigint + 2;
                rendered := CASE WHEN render_value THEN '"' || input_value || '"' ELSE NULL END;
                RETURN NEXT;
                RETURN;
            END IF;
            encoded := pg_catalog.convert_to(input_value, 'UTF8');
            input_bytes := pg_catalog.octet_length(encoded);
            WHILE position < input_bytes LOOP
                first_byte := pg_catalog.get_byte(encoded, position);
                IF first_byte < 128 THEN
                    codepoint := first_byte;
                    position := position + 1;
                ELSIF first_byte BETWEEN 194 AND 223 AND position + 1 < input_bytes THEN
                    codepoint := (first_byte - 192) * 64
                        + pg_catalog.get_byte(encoded, position + 1) - 128;
                    position := position + 2;
                ELSIF first_byte BETWEEN 224 AND 239 AND position + 2 < input_bytes THEN
                    codepoint := (first_byte - 224) * 4096
                        + (pg_catalog.get_byte(encoded, position + 1) - 128) * 64
                        + pg_catalog.get_byte(encoded, position + 2) - 128;
                    position := position + 3;
                ELSIF first_byte BETWEEN 240 AND 244 AND position + 3 < input_bytes THEN
                    codepoint := (first_byte - 240) * 262144
                        + (pg_catalog.get_byte(encoded, position + 1) - 128) * 4096
                        + (pg_catalog.get_byte(encoded, position + 2) - 128) * 64
                        + pg_catalog.get_byte(encoded, position + 3) - 128;
                    position := position + 4;
                ELSE
                    RAISE EXCEPTION 'authority wire JSON string is not UTF8';
                END IF;
                -- convert_to supplied valid UTF8; these are explicit protocol
                -- exclusions, not permission to accept malformed source bytes.
                IF codepoint = 0 OR codepoint BETWEEN 55296 AND 57343 OR codepoint > 1114111 THEN
                    RAISE EXCEPTION 'authority wire JSON string contains an unsupported scalar';
                END IF;
                width := CASE
                    WHEN codepoint IN (8, 9, 10, 12, 13, 34, 92) THEN 2
                    WHEN codepoint BETWEEN 32 AND 126 THEN 1
                    WHEN codepoint < 65536 THEN 6 ELSE 12 END;
                IF emitted_bytes + width > maximum_bytes THEN
                    RAISE EXCEPTION 'authority wire JSON byte bound exceeded';
                END IF;
                emitted_bytes := emitted_bytes + width;
                IF render_value THEN
                    fragment := CASE codepoint
                        WHEN 8 THEN slash || 'b' WHEN 9 THEN slash || 't'
                        WHEN 10 THEN slash || 'n' WHEN 12 THEN slash || 'f'
                        WHEN 13 THEN slash || 'r' WHEN 34 THEN slash || '"'
                        WHEN 92 THEN slash || slash
                        ELSE CASE WHEN codepoint BETWEEN 32 AND 126
                            THEN pg_catalog.chr(codepoint)
                            WHEN codepoint < 65536 THEN slash || 'u'
                                || pg_catalog.lpad(pg_catalog.to_hex(codepoint), 4, '0')
                            ELSE slash || 'u' || pg_catalog.to_hex(55296 + ((codepoint - 65536) / 1024))
                                || slash || 'u' || pg_catalog.to_hex(56320 + ((codepoint - 65536) % 1024))
                            END
                        END;
                    chunk := chunk || fragment;
                    IF pg_catalog.octet_length(chunk) >= 8192 THEN
                        parts := pg_catalog.array_append(parts, chunk);
                        chunk := '';
                    END IF;
                END IF;
            END LOOP;
            IF render_value THEN
                parts := pg_catalog.array_append(parts, chunk);
                rendered := '"' || pg_catalog.array_to_string(parts, '') || '"';
                IF pg_catalog.octet_length(rendered) <> emitted_bytes THEN
                    RAISE EXCEPTION 'authority wire JSON string measurement changed';
                END IF;
            ELSE
                rendered := NULL;
            END IF;
            RETURN NEXT;
        END;
        $catchplate_wire_string$;

        CREATE OR REPLACE FUNCTION {namespace}.catchplate_policy_authority_wire_walk(
            input_value pg_catalog.jsonb, remaining_depth integer,
            maximum_nodes bigint, maximum_bytes bigint, render_value boolean
        ) RETURNS TABLE(rendered text, visited_nodes bigint, emitted_bytes bigint)
        LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER
        SET search_path = pg_catalog
        AS $catchplate_wire_walk$
        DECLARE
            kind text;
            scalar text;
            entry record;
            child record;
            quoted record;
            separator_bytes integer;
            count_members bigint := 0;
            parts text[] := ARRAY[]::text[];
        BEGIN
            IF pg_catalog.getdatabaseencoding() IS DISTINCT FROM 'UTF8' THEN
                RAISE EXCEPTION 'authority wire JSON requires a UTF8 database';
            END IF;
            IF remaining_depth NOT BETWEEN 0 AND {WIRE_JSON_MAX_DEPTH} THEN
                RAISE EXCEPTION 'authority wire JSON depth bound exceeded';
            END IF;
            IF maximum_nodes NOT BETWEEN 1 AND {WIRE_JSON_MAX_NODES} THEN
                RAISE EXCEPTION 'authority wire JSON node bound exceeded';
            END IF;
            IF maximum_bytes NOT BETWEEN 1 AND {WIRE_JSON_MAX_BYTES} THEN
                RAISE EXCEPTION 'authority wire JSON byte bound exceeded';
            END IF;
            kind := pg_catalog.jsonb_typeof(input_value);
            visited_nodes := 1;
            rendered := NULL;
            IF kind = 'string' THEN
                SELECT * INTO STRICT quoted FROM {namespace}.catchplate_policy_authority_wire_string(
                    input_value #>> '{{}}', render_value, maximum_bytes);
                emitted_bytes := quoted.emitted_bytes;
                rendered := quoted.rendered;
            ELSIF kind IN ('null', 'boolean', 'number') THEN
                scalar := input_value::text;
                IF kind = 'number' AND scalar !~ '^-?(0|[1-9][0-9]*)$' THEN
                    RAISE EXCEPTION 'authority wire JSON requires lossless integer numbers';
                END IF;
                emitted_bytes := pg_catalog.octet_length(scalar);
                IF emitted_bytes > maximum_bytes THEN
                    RAISE EXCEPTION 'authority wire JSON byte bound exceeded';
                END IF;
                IF render_value THEN rendered := scalar; END IF;
            ELSIF kind IN ('array', 'object') THEN
                emitted_bytes := 2;
                IF emitted_bytes > maximum_bytes THEN
                    RAISE EXCEPTION 'authority wire JSON byte bound exceeded';
                END IF;
                IF kind = 'array' THEN
                    IF pg_catalog.jsonb_array_length(input_value)::bigint > maximum_nodes - 1 THEN
                        RAISE EXCEPTION 'authority wire JSON node bound exceeded';
                    END IF;
                    FOR entry IN SELECT value FROM pg_catalog.jsonb_array_elements(input_value) LOOP
                        separator_bytes := CASE WHEN count_members = 0 THEN 0 ELSE 1 END;
                        SELECT * INTO STRICT child FROM {namespace}.catchplate_policy_authority_wire_walk(
                            entry.value, remaining_depth - 1, maximum_nodes - visited_nodes,
                            maximum_bytes - emitted_bytes - separator_bytes, render_value);
                        visited_nodes := visited_nodes + child.visited_nodes;
                        emitted_bytes := emitted_bytes + separator_bytes + child.emitted_bytes;
                        IF render_value THEN parts := pg_catalog.array_append(parts, child.rendered); END IF;
                        count_members := count_members + 1;
                    END LOOP;
                ELSE
                    -- Key order does not affect measurement; rendering alone
                    -- needs C ordering. The measure pass collects no output.
                    FOR entry IN SELECT key, value FROM pg_catalog.jsonb_each(input_value)
                        ORDER BY CASE WHEN render_value THEN key ELSE NULL END COLLATE "C"
                    LOOP
                        IF visited_nodes + 2 > maximum_nodes THEN
                            RAISE EXCEPTION 'authority wire JSON node bound exceeded';
                        END IF;
                        IF remaining_depth = 0 THEN
                            RAISE EXCEPTION 'authority wire JSON depth bound exceeded';
                        END IF;
                        separator_bytes := CASE WHEN count_members = 0 THEN 1 ELSE 2 END;
                        SELECT * INTO STRICT quoted FROM {namespace}.catchplate_policy_authority_wire_string(
                            entry.key, render_value, maximum_bytes - emitted_bytes - separator_bytes);
                        SELECT * INTO STRICT child FROM {namespace}.catchplate_policy_authority_wire_walk(
                            entry.value, remaining_depth - 1, maximum_nodes - visited_nodes - 1,
                            maximum_bytes - emitted_bytes - separator_bytes - quoted.emitted_bytes, render_value);
                        visited_nodes := visited_nodes + 1 + child.visited_nodes;
                        emitted_bytes := emitted_bytes + separator_bytes + quoted.emitted_bytes + child.emitted_bytes;
                        IF render_value THEN
                            parts := pg_catalog.array_append(parts, quoted.rendered || ':' || child.rendered);
                        END IF;
                        count_members := count_members + 1;
                    END LOOP;
                END IF;
                IF render_value THEN
                    rendered := CASE WHEN kind = 'array' THEN '[' ELSE '{{' END
                        || pg_catalog.array_to_string(parts, ',')
                        || CASE WHEN kind = 'array' THEN ']' ELSE '}}' END;
                END IF;
            ELSE
                RAISE EXCEPTION 'authority wire JSON value type is unsupported';
            END IF;
            IF render_value AND pg_catalog.octet_length(rendered) IS DISTINCT FROM emitted_bytes THEN
                RAISE EXCEPTION 'authority wire JSON measurement changed';
            END IF;
            RETURN NEXT;
        END;
        $catchplate_wire_walk$;

        CREATE OR REPLACE FUNCTION {namespace}.catchplate_policy_authority_wire_json(input_value pg_catalog.jsonb)
        RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER
        SET search_path = pg_catalog
        AS $catchplate_wire_json$
        DECLARE
            measured record;
            encoded record;
        BEGIN
            SELECT * INTO STRICT measured FROM {namespace}.catchplate_policy_authority_wire_walk(
                input_value, {WIRE_JSON_MAX_DEPTH}, {WIRE_JSON_MAX_NODES}, {WIRE_JSON_MAX_BYTES}, FALSE);
            SELECT * INTO STRICT encoded FROM {namespace}.catchplate_policy_authority_wire_walk(
                input_value, {WIRE_JSON_MAX_DEPTH}, measured.visited_nodes, measured.emitted_bytes, TRUE);
            IF encoded.visited_nodes IS DISTINCT FROM measured.visited_nodes
                OR encoded.emitted_bytes IS DISTINCT FROM measured.emitted_bytes
                OR pg_catalog.octet_length(encoded.rendered) IS DISTINCT FROM measured.emitted_bytes
            THEN RAISE EXCEPTION 'authority wire JSON preflight changed'; END IF;
            RETURN encoded.rendered;
        END;
        $catchplate_wire_json$;
    """)
