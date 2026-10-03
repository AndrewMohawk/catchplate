"""All-profile dispatch for one normalized counted-index event.

The dispatcher locks the complete fixed head set before invoking actual path
maintenance. Direct JSONB calls do not authenticate OLD/NEW images. Production
source now wires the real primary trigger's normalized event boundary and
catalog/owner/ACL checks. Runtime admission, independently admitted root vectors
and operation-global work accounting remain due. No trigger is attached here.
"""
from __future__ import annotations

import re

from serverware import authority_index_contract as contract
from serverware import authority_index_projection as projection


# Fixed ceiling for the five activation-delivery profiles, not a caller budget.
MAX_EVENT_PROFILES = 5
COUNTED_MAINTENANCE_FUNCTION_NAMES = (
    "serverware_policy_authority_counted_apply_event",
)


def counted_maintenance_functions_sql(namespace: str) -> tuple[str, ...]:
    """Render one invoker function after the real path and store definitions.

    Only source-fixed tables select profiles. The caller cannot select a subset,
    pass a root or successful verifier result, adjust limits, or synthesize genesis.
    Each required head costs one additional canonical-empty hash before path calls;
    the per-profile component's own work remains separately chargeable.
    """
    if type(namespace) is not str or re.fullmatch(r'"[a-z][a-z0-9_]{0,62}"', namespace) is None:
        raise ValueError("counted maintenance namespace must be an exact quoted identifier")
    profiles = tuple(projection.profile_for(index_id) for index_id in projection.INDEX_IDS)
    tables = tuple(sorted({profile.table for profile in profiles}))
    groups = tuple((table, projection.index_ids_for_table(table)) for table in tables)
    if not groups or any(not ids or len(ids) > MAX_EVENT_PROFILES for _, ids in groups):
        raise ValueError("counted maintenance source profile fanout exceeds its fixed bound")
    cases = "\n                ".join(
        f"WHEN '{table}' THEN ARRAY[" + ", ".join(f"'{index_id}'" for index_id in ids) + "]::text[]"
        for table, ids in groups
    )
    manifest_digest = projection.projection_manifest_digest()
    return (
        f"""
        CREATE OR REPLACE FUNCTION {namespace}.serverware_policy_authority_counted_apply_event(
            authenticated_table text, mutation_operation text, old_row jsonb, new_row jsonb
        ) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $counted_event$
        DECLARE
            source_ids text[];
            source_index text;
            source_head record;
            candidate record;
            head_count integer;
            expected_table text;
            expected_projection text;
            expected_empty text;
            old_id text;
            new_id text;
        BEGIN
            IF authenticated_table IS NULL
                OR pg_catalog.octet_length(authenticated_table) NOT BETWEEN 1 AND 128
                OR mutation_operation IS NULL
                OR pg_catalog.octet_length(mutation_operation) <> 6
                OR mutation_operation COLLATE "C" NOT IN ('INSERT', 'UPDATE', 'DELETE')
            THEN RAISE EXCEPTION 'counted event table or operation is invalid'; END IF;
            source_ids := CASE authenticated_table COLLATE "C"
                {cases}
                ELSE NULL
            END;
            IF source_ids IS NULL THEN
                RAISE EXCEPTION 'counted event table has no admitted source profiles';
            END IF;
            IF (mutation_operation COLLATE "C" = 'INSERT' AND (old_row IS NOT NULL OR new_row IS NULL))
                OR (mutation_operation COLLATE "C" = 'DELETE' AND (old_row IS NULL OR new_row IS NOT NULL))
                OR (mutation_operation COLLATE "C" = 'UPDATE' AND (old_row IS NULL OR new_row IS NULL))
                OR (old_row IS NOT NULL AND pg_catalog.jsonb_typeof(old_row) <> 'object')
                OR (new_row IS NOT NULL AND pg_catalog.jsonb_typeof(new_row) <> 'object')
            THEN RAISE EXCEPTION 'counted event requires exact normalized row images'; END IF;
            IF old_row IS NOT NULL THEN
                old_id := {namespace}.serverware_policy_authority_counted_field(old_row, 'id', 'text') #>> '{{}}';
            END IF;
            IF new_row IS NOT NULL THEN
                new_id := {namespace}.serverware_policy_authority_counted_field(new_row, 'id', 'text') #>> '{{}}';
            END IF;
            IF mutation_operation COLLATE "C" = 'UPDATE' AND old_id COLLATE "C" IS DISTINCT FROM new_id COLLATE "C" THEN
                RAISE EXCEPTION 'counted key-changing update requires normalized delete and insert';
            END IF;

            -- Source IDs are exact ASCII identifiers sorted in Python byte
            -- order. Lock/check every required head before any path can write,
            -- including profiles for which both rows will be nonmembers.
            FOREACH source_index IN ARRAY source_ids LOOP
                head_count := 0;
                FOR candidate IN
                    SELECT
                        CASE WHEN pg_catalog.octet_length(head.index_id) <= 128 THEN head.index_id ELSE NULL END AS index_id,
                        CASE WHEN pg_catalog.octet_length(head.table_name) <= 128 THEN head.table_name ELSE NULL END AS table_name,
                        CASE WHEN pg_catalog.octet_length(head.counted_profile) <= 128 THEN head.counted_profile ELSE NULL END AS counted_profile,
                        CASE WHEN pg_catalog.octet_length(head.projection_digest) <= 71 THEN head.projection_digest ELSE NULL END AS projection_digest,
                        CASE WHEN pg_catalog.octet_length(head.projection_manifest_digest) <= 71 THEN head.projection_manifest_digest ELSE NULL END AS projection_manifest_digest,
                        head.index_revision,
                        CASE WHEN pg_catalog.octet_length(head.root_digest) <= 71 THEN head.root_digest ELSE NULL END AS root_digest,
                        head.leaf_count
                    FROM {namespace}.policy_authority_counted_index_heads AS head
                    WHERE head.index_id COLLATE "C" = source_index COLLATE "C"
                    LIMIT 2 FOR UPDATE
                LOOP
                    head_count := head_count + 1;
                    IF head_count > 1 THEN RAISE EXCEPTION 'counted event required head is not unique'; END IF;
                    source_head := candidate;
                END LOOP;
                IF head_count <> 1 THEN RAISE EXCEPTION 'counted event required head is absent'; END IF;
                SELECT profile.table_name, profile.projection_digest
                    INTO expected_table, expected_projection
                FROM {namespace}.serverware_policy_authority_counted_profile(source_index) AS profile;
                IF source_head.index_id COLLATE "C" IS DISTINCT FROM source_index COLLATE "C"
                    OR expected_table COLLATE "C" IS DISTINCT FROM authenticated_table COLLATE "C"
                    OR source_head.table_name COLLATE "C" IS DISTINCT FROM expected_table COLLATE "C"
                    OR source_head.counted_profile COLLATE "C" IS DISTINCT FROM '{contract.PROFILE}' COLLATE "C"
                    OR source_head.projection_digest COLLATE "C" IS DISTINCT FROM expected_projection COLLATE "C"
                    OR source_head.projection_manifest_digest COLLATE "C" IS DISTINCT FROM '{manifest_digest}' COLLATE "C"
                    OR source_head.index_revision IS NULL OR source_head.index_revision < 0
                    OR source_head.leaf_count IS NULL OR source_head.leaf_count < 0
                    OR source_head.root_digest IS NULL OR pg_catalog.octet_length(source_head.root_digest) <> 71
                    OR pg_catalog.substr(source_head.root_digest, 1, 7) COLLATE "C" <> 'sha256:' COLLATE "C"
                    OR pg_catalog.translate(pg_catalog.substr(source_head.root_digest, 8), '0123456789abcdef', '') COLLATE "C" <> '' COLLATE "C"
                    OR (source_head.index_revision = 0 AND source_head.leaf_count <> 0)
                THEN RAISE EXCEPTION 'counted event required head contract differs'; END IF;
                expected_empty := {namespace}.serverware_policy_authority_counted_empty(source_index, '');
                IF (source_head.leaf_count = 0) IS DISTINCT FROM (source_head.root_digest COLLATE "C" = expected_empty COLLATE "C") THEN
                    RAISE EXCEPTION 'counted event required head empty convention differs';
                END IF;
            END LOOP;

            -- No exception is swallowed and no transaction is committed.
            -- Failure in a later profile rolls back earlier effects of this
            -- same SQL statement; a successful call is not a release receipt.
            FOREACH source_index IN ARRAY source_ids LOOP
                PERFORM {namespace}.serverware_policy_authority_counted_apply_index(
                    source_index, mutation_operation, old_row, new_row);
            END LOOP;
        END;
        $counted_event$
        """,
    )
