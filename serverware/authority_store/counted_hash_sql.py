"""PostgreSQL counted-index hash definitions, in dependency order.

The eleven profile identities/digests are rendered from current source codecs.
These immutable invoker functions install no tables, triggers, privileges or
heads and confer no index-population, checkpoint or operation authority. Their
closed framing helper does not change the persisted primary-tree hash helper.
The counted installer consumes these definitions; runtime admission is separate.
"""
from __future__ import annotations

import re

from serverware import authority_index_projection as projection


_COUNTED = "serverware.policyAuthorityCountedIndex/v1"
_EMPTY = "serverware.policyAuthorityCountedIndexEmpty/v1"
_LEAF = "serverware.policyAuthorityCountedIndexLeaf/v1"
_BRANCH = "serverware.policyAuthorityCountedIndexNode/v1"
_I64 = 2**63 - 1
COUNTED_HASH_FUNCTION_NAMES = (
    "serverware_policy_authority_counted_profile",
    "serverware_policy_authority_counted_frame_digest",
    "serverware_policy_authority_counted_empty",
    "serverware_policy_authority_counted_leaf",
    "serverware_policy_authority_counted_branch",
)


def counted_hash_functions_sql(namespace: str) -> tuple[str, ...]:
    """Render five bounded PG16 definitions; accept only a quoted namespace."""
    if type(namespace) is not str or re.fullmatch(r'"[a-z][a-z0-9_]{0,62}"', namespace) is None:
        raise ValueError("counted hash namespace must be an exact quoted identifier")
    profiles = tuple(projection.profile_for(index_id) for index_id in projection.INDEX_IDS)
    # Every scalar here is a validated source ASCII identifier/canonical digest,
    # not caller SQL. Keep the profile rows closed; unknown identities raise.
    profile_values = ",\n                    ".join(
        f"('{profile.index_id}', '{profile.table}', '{profile.projection_digest}')"
        for profile in profiles)
    return (
        f"""
        CREATE OR REPLACE FUNCTION {namespace}.serverware_policy_authority_counted_profile(
            index_identity text
        ) RETURNS TABLE(table_name text, projection_digest text)
        LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $counted_profile$
        BEGIN
            IF index_identity IS NULL OR pg_catalog.octet_length(index_identity) NOT BETWEEN 1 AND 128 THEN
                RAISE EXCEPTION 'counted index identity is outside its fixed bound';
            END IF;
            SELECT source.table_name, source.projection_digest INTO table_name, projection_digest
            FROM (VALUES
                    {profile_values}
            ) AS source(index_id, table_name, projection_digest)
            WHERE source.index_id COLLATE "C" = index_identity COLLATE "C";
            IF NOT FOUND THEN
                RAISE EXCEPTION 'counted index identity is not source admitted';
            END IF;
            RETURN NEXT;
        END;
        $counted_profile$
        """,
        f"""
        CREATE OR REPLACE FUNCTION {namespace}.serverware_policy_authority_counted_frame_digest(
            digest_domain text, digest_frames text[]
        ) RETURNS text
        LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $counted_frame$
        DECLARE
            frame_count integer;
            material bytea;
            encoded bytea;
            frame text;
        BEGIN
            IF digest_domain IS NULL OR digest_frames IS NULL THEN
                RAISE EXCEPTION 'counted framing inputs cannot be null';
            END IF;
            frame_count := CASE digest_domain COLLATE "C"
                WHEN '{_EMPTY}' THEN 8
                WHEN '{_LEAF}' THEN 10
                WHEN '{_BRANCH}' THEN 40
                ELSE 0 END;
            IF frame_count = 0
                OR pg_catalog.array_ndims(digest_frames) IS DISTINCT FROM 1
                OR pg_catalog.array_lower(digest_frames, 1) IS DISTINCT FROM 1
                OR pg_catalog.array_upper(digest_frames, 1) IS DISTINCT FROM frame_count THEN
                RAISE EXCEPTION 'counted framing domain or array shape is invalid';
            END IF;
            encoded := pg_catalog.convert_to(digest_domain, 'UTF8');
            material := pg_catalog.int8send(pg_catalog.octet_length(encoded)::bigint) || encoded;
            FOREACH frame IN ARRAY digest_frames LOOP
                IF frame IS NULL OR pg_catalog.octet_length(frame) > 160 THEN
                    RAISE EXCEPTION 'counted frame is null or exceeds its fixed bound';
                END IF;
                encoded := pg_catalog.convert_to(frame, 'UTF8');
                IF pg_catalog.octet_length(encoded) > 160
                    OR pg_catalog.octet_length(encoded) <> pg_catalog.char_length(frame) THEN
                    RAISE EXCEPTION 'counted frame is not bounded ASCII';
                END IF;
                material := material || pg_catalog.int8send(pg_catalog.octet_length(encoded)::bigint) || encoded;
            END LOOP;
            RETURN 'sha256:' || pg_catalog.encode(pg_catalog.sha256(material), 'hex');
        END;
        $counted_frame$
        """,
        f"""
        CREATE OR REPLACE FUNCTION {namespace}.serverware_policy_authority_counted_empty(
            index_identity text, path_prefix text
        ) RETURNS text
        LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $counted_empty$
        DECLARE
            source_table text;
            source_projection text;
        BEGIN
            IF path_prefix IS NULL OR pg_catalog.octet_length(path_prefix) > 160
                OR pg_catalog.translate(path_prefix, '0123456789abcdef', '') COLLATE "C" <> '' COLLATE "C" THEN
                RAISE EXCEPTION 'counted empty prefix is invalid';
            END IF;
            SELECT profile.table_name, profile.projection_digest INTO STRICT source_table, source_projection
            FROM {namespace}.serverware_policy_authority_counted_profile(index_identity) AS profile;
            RETURN {namespace}.serverware_policy_authority_counted_frame_digest('{_EMPTY}', ARRAY[
                '{_COUNTED}', index_identity, source_table, source_projection, '160',
                pg_catalog.char_length(path_prefix)::text, path_prefix, '0'
            ]::text[]);
        END;
        $counted_empty$
        """,
        f"""
        CREATE OR REPLACE FUNCTION {namespace}.serverware_policy_authority_counted_leaf(
            index_identity text, index_key text, primary_key_digest text, primary_row_digest text
        ) RETURNS text
        LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $counted_leaf$
        DECLARE
            source_table text;
            source_projection text;
            supplied_digest text;
        BEGIN
            IF index_key IS NULL OR pg_catalog.octet_length(index_key) <> 160
                OR pg_catalog.translate(index_key, '0123456789abcdef', '') COLLATE "C" <> '' COLLATE "C" THEN
                RAISE EXCEPTION 'counted leaf key is invalid';
            END IF;
            FOREACH supplied_digest IN ARRAY ARRAY[primary_key_digest, primary_row_digest] LOOP
                IF supplied_digest IS NULL OR pg_catalog.octet_length(supplied_digest) <> 71
                    OR pg_catalog.substr(supplied_digest, 1, 7) COLLATE "C" <> 'sha256:' COLLATE "C"
                    OR pg_catalog.translate(pg_catalog.substr(supplied_digest, 8), '0123456789abcdef', '') COLLATE "C" <> '' COLLATE "C" THEN
                    RAISE EXCEPTION 'counted leaf commitment is invalid';
                END IF;
            END LOOP;
            SELECT profile.table_name, profile.projection_digest INTO STRICT source_table, source_projection
            FROM {namespace}.serverware_policy_authority_counted_profile(index_identity) AS profile;
            RETURN {namespace}.serverware_policy_authority_counted_frame_digest('{_LEAF}', ARRAY[
                '{_COUNTED}', index_identity, source_table, source_projection, '160',
                '160', index_key, '1', primary_key_digest, primary_row_digest
            ]::text[]);
        END;
        $counted_leaf$
        """,
        f"""
        CREATE OR REPLACE FUNCTION {namespace}.serverware_policy_authority_counted_branch(
            index_identity text, path_prefix text, child_digests text[], child_counts bigint[]
        ) RETURNS TABLE(node_digest text, subtree_count bigint)
        LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $counted_branch$
        DECLARE
            source_table text;
            source_projection text;
            prefix_depth integer;
            child_capacity bigint;
            total_count bigint := 0;
            slot integer;
            child_digest text;
            frames text[];
        BEGIN
            IF path_prefix IS NULL OR pg_catalog.octet_length(path_prefix) > 159
                OR pg_catalog.translate(path_prefix, '0123456789abcdef', '') COLLATE "C" <> '' COLLATE "C" THEN
                RAISE EXCEPTION 'counted branch prefix is invalid';
            END IF;
            IF child_digests IS NULL OR child_counts IS NULL
                OR pg_catalog.array_ndims(child_digests) IS DISTINCT FROM 1
                OR pg_catalog.array_ndims(child_counts) IS DISTINCT FROM 1
                OR pg_catalog.array_lower(child_digests, 1) IS DISTINCT FROM 1
                OR pg_catalog.array_lower(child_counts, 1) IS DISTINCT FROM 1
                OR pg_catalog.array_upper(child_digests, 1) IS DISTINCT FROM 16
                OR pg_catalog.array_upper(child_counts, 1) IS DISTINCT FROM 16 THEN
                RAISE EXCEPTION 'counted branch arrays must be one-dimensional one-based sixteen slots';
            END IF;
            SELECT profile.table_name, profile.projection_digest INTO STRICT source_table, source_projection
            FROM {namespace}.serverware_policy_authority_counted_profile(index_identity) AS profile;
            prefix_depth := pg_catalog.char_length(path_prefix);
            child_capacity := CASE WHEN 159 - prefix_depth >= 16 THEN {_I64}
                ELSE (1::bigint << (4 * (159 - prefix_depth))) END;
            -- Admit every child/count and the total before any empty-child or
            -- branch hash. Paired NULLs, never explicit zero, mean emptiness.
            FOR slot IN 1..16 LOOP
                IF child_digests[slot] IS NULL AND child_counts[slot] IS NULL THEN
                    CONTINUE;
                END IF;
                child_digest := child_digests[slot];
                IF child_digest IS NULL OR child_counts[slot] IS NULL
                    OR child_counts[slot] NOT BETWEEN 1 AND child_capacity
                    OR pg_catalog.octet_length(child_digest) <> 71
                    OR pg_catalog.substr(child_digest, 1, 7) COLLATE "C" <> 'sha256:' COLLATE "C"
                    OR pg_catalog.translate(pg_catalog.substr(child_digest, 8), '0123456789abcdef', '') COLLATE "C" <> '' COLLATE "C" THEN
                    RAISE EXCEPTION 'counted branch child commitment or count is invalid';
                END IF;
                IF child_counts[slot] > {_I64} - total_count THEN
                    RAISE EXCEPTION 'counted branch count overflows int64';
                END IF;
                total_count := total_count + child_counts[slot];
            END LOOP;
            subtree_count := total_count;
            IF total_count = 0 THEN
                node_digest := {namespace}.serverware_policy_authority_counted_empty(index_identity, path_prefix);
                RETURN NEXT;
                RETURN;
            END IF;
            frames := ARRAY['{_COUNTED}', index_identity, source_table, source_projection,
                            '160', prefix_depth::text, path_prefix, total_count::text]::text[];
            FOR slot IN 1..16 LOOP
                IF child_digests[slot] IS NULL THEN
                    child_digest := {namespace}.serverware_policy_authority_counted_empty(
                        index_identity, path_prefix || pg_catalog.substr('0123456789abcdef', slot, 1));
                    frames := pg_catalog.array_append(pg_catalog.array_append(frames, child_digest), '0');
                ELSE
                    frames := pg_catalog.array_append(pg_catalog.array_append(frames, child_digests[slot]),
                                                      child_counts[slot]::text);
                END IF;
            END LOOP;
            node_digest := {namespace}.serverware_policy_authority_counted_frame_digest('{_BRANCH}', frames);
            RETURN NEXT;
        END;
        $counted_branch$
        """,
    )
