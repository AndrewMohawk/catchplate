"""Uninstalled bounded per-profile counted maintenance, not writer authority.

The invoker function uses actual SQL projections and hashes, locks its head and
rejects corrupt opened caches before writing. A direct JSONB call does not
authenticate OLD/NEW provenance, primary membership, enrollment or currentness.
Its source ceilings apply to one profile/event, not a multirow transaction.
The all-profile dispatcher, real row hook and ACL admission remain separate.
"""
from __future__ import annotations

from serverware import authority_index_contract as contract
from serverware import authority_index_projection as projection
from serverware.authority_store.primary_tree_sql import _namespace


COUNTED_PATH_FUNCTION_NAMES = ("serverware_policy_authority_counted_apply_index",)
MAX_PATH_TARGETS = 2
MAX_PATH_OPENED_NODES = 320
MAX_PATH_CHILD_SLOTS = 16 * MAX_PATH_OPENED_NODES
# Per fold, a positive branch costs at most sixteen actual hashes and an
# empty branch one. Charge two terminal leaves per fold conservatively, plus
# two three-hash member projections, two identity hashes and one head-empty
# hash. The current normalized implementation actually uses at most one
# OLD/NEW terminal per fold and one independent identity hash.
MAX_PATH_HASHES = 2 * (16 * MAX_PATH_OPENED_NODES + MAX_PATH_TARGETS) + 9
# Joint OLD+NEW wire-walk bytes PLUS every returned stored scalar frame.
# Repeated physical leaf reads are deliberately charged repeatedly. This is
# input accounting, not total temporary allocation or repeated hash-input work.
MAX_PATH_INPUT_BYTES = 64 * 1024 * 1024
MAX_PATH_STORED_BYTES = 4 * 1024 * 1024
MAX_PATH_JSON_NODES = 1_000_000
MAX_PATH_NODE_BATCH = 256


def _text(column: str, maximum: int) -> str:
    return (f"CASE WHEN pg_catalog.octet_length({column}) <= {maximum} "
            f"THEN {column} ELSE NULL END")


def _digest(value: str) -> str:
    return (f"({value} IS NOT NULL AND pg_catalog.octet_length({value}) = 71 "
            f"AND pg_catalog.substr({value},1,7) COLLATE \"C\" = 'sha256:' COLLATE \"C\" "
            f"AND pg_catalog.translate(pg_catalog.substr({value},8),'0123456789abcdef','') "
            "COLLATE \"C\" = '' COLLATE \"C\")")


def _frames(*values: str) -> str:
    return " + ".join(f"8 + pg_catalog.octet_length(({value})::text)" for value in values)


def counted_path_functions_sql(namespace: str) -> tuple[str, ...]:
    """Render the real fixed per-index mutation function; install nothing.

    Requires the dedicated DDL, counted project/field/hash functions and genuine
    primary/wire helpers in the same admitted namespace. Bounded scalar-array
    storage is not a PostgreSQL parser/detoast or query-plan allocation proof.
    """
    namespace = _namespace(namespace)
    manifest = projection.projection_manifest_digest()
    leaf_columns = f"""{_text('l.index_id',128)} AS index_id,{_text('l.projection_digest',71)} AS projection_digest,
                        {_text('l.index_key',160)} AS index_key,{_text('l.primary_id',4096)} AS primary_id,
                        {_text('l.primary_key_digest',71)} AS primary_key_digest,
                        {_text('l.primary_row_digest',71)} AS primary_row_digest,l.index_revision"""
    return (f"""
        CREATE OR REPLACE FUNCTION {namespace}.serverware_policy_authority_counted_apply_index(
            index_identity text, mutation_operation text, old_row jsonb, new_row jsonb
        ) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $counted_path$
        DECLARE
            source_table text;
            source_projection text;
            current_head record;
            candidate record;
            measured record;
            projected record;
            folded record;
            row_image jsonb;
            image_number integer;
            old_id text;
            new_id text;
            event_id text;
            identity_digest text;
            old_key text;
            new_key text;
            old_row_digest text;
            new_row_digest text;
            old_leaf_digest text;
            new_leaf_digest text;
            empty_root text;
            old_member boolean := false;
            new_member boolean := false;
            row_bytes bigint := 0;
            row_nodes bigint := 0;
            stored_bytes bigint := 0;
            seen integer;
            lookup_number integer;
            expect_old boolean;
            target_keys text[] := ARRAY[]::text[];
            opened text[] := ARRAY['']::text[];
            requested_prefixes text[] := ARRAY[]::text[];
            requested_depths integer[] := ARRAY[]::integer[];
            cached_digests text[];
            cached_counts bigint[];
            before_digests text[];
            before_counts bigint[];
            after_digests text[];
            after_counts bigint[];
            before_children text[];
            before_child_counts bigint[];
            after_children text[];
            after_child_counts bigint[];
            target text;
            prefix text;
            child_prefix text;
            depth_number integer;
            parent_number integer;
            child_number integer;
            child_open integer;
            slot integer;
            batch_start integer;
            batch_end integer;
            opened_count integer;
            child_slots integer;
            root_number integer;
            next_revision bigint;
        BEGIN
            IF mutation_operation IS NULL OR pg_catalog.octet_length(mutation_operation) <> 6
                OR mutation_operation COLLATE "C" NOT IN ('INSERT','UPDATE','DELETE')
                OR (mutation_operation COLLATE "C" = 'INSERT' AND (old_row IS NOT NULL OR new_row IS NULL))
                OR (mutation_operation COLLATE "C" = 'DELETE' AND (old_row IS NULL OR new_row IS NOT NULL))
                OR (mutation_operation COLLATE "C" = 'UPDATE' AND (old_row IS NULL OR new_row IS NULL))
            THEN RAISE EXCEPTION 'counted path mutation lifecycle is invalid'; END IF;
            SELECT p.table_name,p.projection_digest INTO STRICT source_table,source_projection
            FROM {namespace}.serverware_policy_authority_counted_profile(index_identity) AS p;

            -- Measure both images jointly before projection, even nonmembers.
            -- JSONB construction happened before entry; this is bounded work
            -- admission, not original-input or allocation provenance.
            FOR image_number IN 1..2 LOOP
                row_image := CASE image_number WHEN 1 THEN old_row ELSE new_row END;
                IF row_image IS NULL THEN CONTINUE; END IF;
                IF pg_catalog.jsonb_typeof(row_image) IS DISTINCT FROM 'object' THEN
                    RAISE EXCEPTION 'counted path row must be an actual object';
                END IF;
                IF row_bytes >= {MAX_PATH_INPUT_BYTES} OR row_nodes >= {MAX_PATH_JSON_NODES} THEN
                    RAISE EXCEPTION 'counted path row work exceeds its shared bound';
                END IF;
                SELECT * INTO STRICT measured FROM {namespace}.serverware_policy_authority_wire_walk(
                    row_image,128,({MAX_PATH_JSON_NODES}-row_nodes)::integer,
                    ({MAX_PATH_INPUT_BYTES}-row_bytes)::integer,FALSE);
                row_bytes := row_bytes + measured.emitted_bytes;
                row_nodes := row_nodes + measured.visited_nodes;
            END LOOP;
            FOR image_number IN 1..2 LOOP
                row_image := CASE image_number WHEN 1 THEN old_row ELSE new_row END;
                IF row_image IS NULL THEN CONTINUE; END IF;
                event_id := {namespace}.serverware_policy_authority_counted_field(row_image,'id','text') #>> '{{}}';
                IF image_number = 1 THEN old_id := event_id; ELSE new_id := event_id; END IF;
                seen := 0;
                FOR projected IN SELECT * FROM {namespace}.serverware_policy_authority_counted_project(
                    index_identity,row_image) LIMIT 2
                LOOP
                    seen := seen + 1;
                    IF seen > 1 OR projected.primary_id COLLATE "C" IS DISTINCT FROM event_id COLLATE "C" THEN
                        RAISE EXCEPTION 'counted path projection is not one exact identity';
                    END IF;
                    IF image_number = 1 THEN
                        old_member := true; old_key := projected.index_key; old_row_digest := projected.primary_row_digest;
                    ELSE
                        new_member := true; new_key := projected.index_key; new_row_digest := projected.primary_row_digest;
                    END IF;
                END LOOP;
            END LOOP;
            IF mutation_operation COLLATE "C" = 'UPDATE' AND old_id COLLATE "C" IS DISTINCT FROM new_id COLLATE "C" THEN
                RAISE EXCEPTION 'counted path key-changing UPDATE requires normalized events';
            END IF;
            event_id := COALESCE(old_id,new_id);
            identity_digest := {namespace}.serverware_policy_authority_domain_digest(
                'serverware.policyAuthorityBusinessKey/v1',source_table,
                {namespace}.serverware_policy_authority_wire_json(pg_catalog.jsonb_build_object('id',event_id)));
            IF old_member AND pg_catalog.substr(old_key,97) COLLATE "C" IS DISTINCT FROM pg_catalog.substr(identity_digest,8) COLLATE "C"
                OR new_member AND pg_catalog.substr(new_key,97) COLLATE "C" IS DISTINCT FROM pg_catalog.substr(identity_digest,8) COLLATE "C"
            THEN RAISE EXCEPTION 'counted path projected key identity changed'; END IF;

            seen := 0;
            FOR candidate IN
                SELECT {_text('h.index_id',128)} AS index_id,{_text('h.table_name',128)} AS table_name,
                    {_text('h.counted_profile',128)} AS counted_profile,{_text('h.projection_digest',71)} AS projection_digest,
                    {_text('h.projection_manifest_digest',71)} AS projection_manifest_digest,
                    h.index_revision,{_text('h.root_digest',71)} AS root_digest,h.leaf_count
                FROM {namespace}.policy_authority_counted_index_heads AS h
                WHERE h.index_id COLLATE "C" = index_identity COLLATE "C" LIMIT 2 FOR UPDATE
            LOOP
                seen := seen + 1;
                IF seen > 1 THEN RAISE EXCEPTION 'counted path head is not unique'; END IF;
                current_head := candidate;
            END LOOP;
            IF seen <> 1 THEN RAISE EXCEPTION 'counted path source head is missing'; END IF;
            IF current_head.index_id COLLATE "C" IS DISTINCT FROM index_identity COLLATE "C"
                OR current_head.table_name COLLATE "C" IS DISTINCT FROM source_table COLLATE "C"
                OR current_head.counted_profile COLLATE "C" IS DISTINCT FROM '{contract.PROFILE}' COLLATE "C"
                OR current_head.projection_digest COLLATE "C" IS DISTINCT FROM source_projection COLLATE "C"
                OR current_head.projection_manifest_digest COLLATE "C" IS DISTINCT FROM '{manifest}' COLLATE "C"
                OR current_head.index_revision IS NULL OR current_head.index_revision < 0
                OR current_head.leaf_count IS NULL OR current_head.leaf_count < 0
                OR NOT {_digest('current_head.root_digest')}
            THEN RAISE EXCEPTION 'counted path head source contract changed'; END IF;
            empty_root := {namespace}.serverware_policy_authority_counted_empty(index_identity,'');
            IF (current_head.leaf_count = 0) IS DISTINCT FROM (current_head.root_digest COLLATE "C" = empty_root COLLATE "C")
                OR (current_head.index_revision = 0 AND current_head.leaf_count <> 0)
            THEN RAISE EXCEPTION 'counted path head empty convention changed'; END IF;
            stored_bytes := {_frames("'head'",'current_head.index_id','current_head.table_name','current_head.counted_profile','current_head.projection_digest','current_head.projection_manifest_digest','current_head.index_revision','current_head.root_digest','current_head.leaf_count')};
            IF stored_bytes > {MAX_PATH_STORED_BYTES} OR stored_bytes > {MAX_PATH_INPUT_BYTES}-row_bytes THEN
                RAISE EXCEPTION 'counted path stored input exceeds its shared byte bound';
            END IF;
            IF old_member THEN target_keys := pg_catalog.array_append(target_keys,old_key); END IF;
            IF new_member AND (NOT old_member OR new_key COLLATE "C" <> old_key COLLATE "C") THEN
                target_keys := pg_catalog.array_append(target_keys,new_key);
            END IF;
            IF pg_catalog.cardinality(target_keys) > {MAX_PATH_TARGETS} THEN
                RAISE EXCEPTION 'counted path target bound exceeded';
            END IF;

            -- Check the unique business identity even with zero projected
            -- targets. A hidden same-ID stale leaf is never repaired away.
            FOR lookup_number IN 0..pg_catalog.cardinality(target_keys) LOOP
                expect_old := old_member AND (lookup_number = 0 OR target_keys[lookup_number] COLLATE "C" = old_key COLLATE "C");
                seen := 0;
                FOR candidate IN
                    SELECT {leaf_columns}
                    FROM {namespace}.policy_authority_counted_index_leaves AS l
                    WHERE lookup_number = 0 AND l.index_id COLLATE "C" = index_identity COLLATE "C"
                      AND l.primary_key_digest COLLATE "C" = identity_digest COLLATE "C"
                    UNION ALL
                    SELECT {leaf_columns}
                    FROM {namespace}.policy_authority_counted_index_leaves AS l
                    WHERE lookup_number > 0 AND l.index_id COLLATE "C" = index_identity COLLATE "C"
                      AND l.index_key COLLATE "C" = target_keys[lookup_number] COLLATE "C"
                    LIMIT 2
                LOOP
                    seen := seen + 1;
                    IF seen > 1 OR NOT expect_old
                        OR candidate.index_id COLLATE "C" IS DISTINCT FROM index_identity COLLATE "C"
                        OR candidate.projection_digest COLLATE "C" IS DISTINCT FROM source_projection COLLATE "C"
                        OR candidate.index_key COLLATE "C" IS DISTINCT FROM old_key COLLATE "C"
                        OR candidate.primary_id COLLATE "C" IS DISTINCT FROM event_id COLLATE "C"
                        OR candidate.primary_key_digest COLLATE "C" IS DISTINCT FROM identity_digest COLLATE "C"
                        OR candidate.primary_row_digest COLLATE "C" IS DISTINCT FROM old_row_digest COLLATE "C"
                        OR candidate.index_revision IS NULL OR candidate.index_revision < 1
                        OR candidate.index_revision > current_head.index_revision
                    THEN RAISE EXCEPTION 'counted path existing leaf differs from exact OLD membership'; END IF;
                    stored_bytes := stored_bytes + {_frames("'leaf'",'candidate.index_id','candidate.projection_digest','candidate.index_key','candidate.primary_id','candidate.primary_key_digest','candidate.primary_row_digest','candidate.index_revision')};
                    IF stored_bytes > {MAX_PATH_STORED_BYTES} OR stored_bytes > {MAX_PATH_INPUT_BYTES}-row_bytes THEN
                        RAISE EXCEPTION 'counted path stored input exceeds its shared byte bound';
                    END IF;
                END LOOP;
                IF expect_old AND seen <> 1 THEN RAISE EXCEPTION 'counted path required OLD leaf is missing'; END IF;
            END LOOP;
            FOREACH target IN ARRAY target_keys LOOP
                FOR depth_number IN 0..159 LOOP
                    prefix := pg_catalog.substr(target,1,depth_number);
                    IF pg_catalog.array_position(opened,prefix) IS NULL THEN
                        IF pg_catalog.cardinality(opened) >= {MAX_PATH_OPENED_NODES} THEN
                            RAISE EXCEPTION 'counted path opened-node bound exceeded';
                        END IF;
                        opened := pg_catalog.array_append(opened,prefix);
                    END IF;
                END LOOP;
            END LOOP;
            -- Aggregate only this already-bounded scalar array. Descendants
            -- precede parents; no relation scan or JSONB tree is accumulated.
            SELECT pg_catalog.array_agg(item.value ORDER BY pg_catalog.char_length(item.value) DESC,item.value COLLATE "C")
            INTO opened FROM pg_catalog.unnest(opened) AS item(value);
            opened_count := pg_catalog.cardinality(opened);
            root_number := pg_catalog.array_position(opened,'');
            FOREACH prefix IN ARRAY opened LOOP
                FOR child_number IN 1..16 LOOP
                    IF pg_catalog.cardinality(requested_prefixes) >= {MAX_PATH_CHILD_SLOTS} THEN
                        RAISE EXCEPTION 'counted path child-slot bound exceeded';
                    END IF;
                    requested_prefixes := pg_catalog.array_append(requested_prefixes,
                        prefix || pg_catalog.substr('0123456789abcdef',child_number,1));
                    requested_depths := pg_catalog.array_append(requested_depths,pg_catalog.char_length(prefix)+1);
                END LOOP;
            END LOOP;
            child_slots := pg_catalog.cardinality(requested_prefixes);
            cached_digests := pg_catalog.array_fill(NULL::text,ARRAY[child_slots]);
            cached_counts := pg_catalog.array_fill(NULL::bigint,ARRAY[child_slots]);
            batch_start := 1;
            WHILE batch_start <= child_slots LOOP
                batch_end := LEAST(batch_start+{MAX_PATH_NODE_BATCH}-1,child_slots);
                seen := 0;
                FOR candidate IN
                    SELECT requested.slot,{_text('n.index_id',128)} AS index_id,
                        {_text('n.projection_digest',71)} AS projection_digest,n.depth,
                        {_text('n.path_prefix',160)} AS path_prefix,{_text('n.node_digest',71)} AS node_digest,
                        n.subtree_count,n.index_revision
                    FROM pg_catalog.generate_series(batch_start,batch_end) AS requested(slot)
                    JOIN {namespace}.policy_authority_counted_index_nodes AS n
                      ON n.depth = requested_depths[requested.slot]
                     AND n.path_prefix COLLATE "C" = requested_prefixes[requested.slot] COLLATE "C"
                    WHERE n.index_id COLLATE "C" = index_identity COLLATE "C"
                    ORDER BY requested.slot LIMIT (batch_end-batch_start+2)
                LOOP
                    seen := seen+1;
                    slot := candidate.slot;
                    IF seen > batch_end-batch_start+1 OR slot IS NULL OR slot NOT BETWEEN batch_start AND batch_end
                        OR cached_digests[slot] IS NOT NULL
                        OR candidate.index_id COLLATE "C" IS DISTINCT FROM index_identity COLLATE "C"
                        OR candidate.projection_digest COLLATE "C" IS DISTINCT FROM source_projection COLLATE "C"
                        OR candidate.depth IS DISTINCT FROM requested_depths[slot]
                        OR candidate.path_prefix COLLATE "C" IS DISTINCT FROM requested_prefixes[slot] COLLATE "C"
                        OR NOT {_digest('candidate.node_digest')}
                        OR candidate.subtree_count IS NULL OR candidate.subtree_count < 1
                        OR candidate.subtree_count > CASE WHEN candidate.depth BETWEEN 145 AND 160
                            THEN (1::bigint << (4*(160-candidate.depth))) ELSE 9223372036854775807::bigint END
                        OR candidate.index_revision IS NULL OR candidate.index_revision < 1
                        OR candidate.index_revision > current_head.index_revision
                    THEN RAISE EXCEPTION 'counted path stored node contract changed'; END IF;
                    stored_bytes := stored_bytes + {_frames("'node'",'candidate.index_id','candidate.projection_digest','candidate.depth','candidate.path_prefix','candidate.node_digest','candidate.subtree_count','candidate.index_revision')};
                    IF stored_bytes > {MAX_PATH_STORED_BYTES} OR stored_bytes > {MAX_PATH_INPUT_BYTES}-row_bytes THEN
                        RAISE EXCEPTION 'counted path stored input exceeds its shared byte bound';
                    END IF;
                    cached_digests[slot] := candidate.node_digest;
                    cached_counts[slot] := candidate.subtree_count;
                END LOOP;
                batch_start := batch_end+1;
            END LOOP;
            IF old_member THEN
                old_leaf_digest := {namespace}.serverware_policy_authority_counted_leaf(
                    index_identity,old_key,identity_digest,old_row_digest);
            END IF;
            IF new_member THEN
                new_leaf_digest := {namespace}.serverware_policy_authority_counted_leaf(
                    index_identity,new_key,identity_digest,new_row_digest);
            END IF;
            before_digests := pg_catalog.array_fill(NULL::text,ARRAY[opened_count]);
            before_counts := pg_catalog.array_fill(0::bigint,ARRAY[opened_count]);
            after_digests := pg_catalog.array_fill(NULL::text,ARRAY[opened_count]);
            after_counts := pg_catalog.array_fill(0::bigint,ARRAY[opened_count]);
            FOR parent_number IN 1..opened_count LOOP
                prefix := opened[parent_number];
                before_children := pg_catalog.array_fill(NULL::text,ARRAY[16]);
                before_child_counts := pg_catalog.array_fill(NULL::bigint,ARRAY[16]);
                after_children := pg_catalog.array_fill(NULL::text,ARRAY[16]);
                after_child_counts := pg_catalog.array_fill(NULL::bigint,ARRAY[16]);
                FOR child_number IN 1..16 LOOP
                    slot := (parent_number-1)*16+child_number;
                    child_prefix := requested_prefixes[slot];
                    child_open := pg_catalog.array_position(opened,child_prefix);
                    IF child_open IS NOT NULL THEN
                        IF child_open >= parent_number THEN
                            RAISE EXCEPTION 'counted path fold order changed';
                        END IF;
                        IF before_counts[child_open] > 0 THEN
                            before_children[child_number] := before_digests[child_open];
                            before_child_counts[child_number] := before_counts[child_open];
                        END IF;
                        IF after_counts[child_open] > 0 THEN
                            after_children[child_number] := after_digests[child_open];
                            after_child_counts[child_number] := after_counts[child_open];
                        END IF;
                    ELSIF pg_catalog.array_position(target_keys,child_prefix) IS NOT NULL THEN
                        -- Target depth160 cache must agree with the actual
                        -- stored OLD leaf, not merely with another cache node.
                        IF old_member AND child_prefix COLLATE "C" = old_key COLLATE "C" THEN
                            before_children[child_number] := old_leaf_digest;
                            before_child_counts[child_number] := 1;
                        END IF;
                        IF new_member AND child_prefix COLLATE "C" = new_key COLLATE "C" THEN
                            after_children[child_number] := new_leaf_digest;
                            after_child_counts[child_number] := 1;
                        END IF;
                        IF cached_digests[slot] IS DISTINCT FROM before_children[child_number]
                            OR cached_counts[slot] IS DISTINCT FROM before_child_counts[child_number]
                        THEN RAISE EXCEPTION 'counted path target node differs from exact OLD leaf'; END IF;
                    ELSE
                        before_children[child_number] := cached_digests[slot];
                        before_child_counts[child_number] := cached_counts[slot];
                        after_children[child_number] := cached_digests[slot];
                        after_child_counts[child_number] := cached_counts[slot];
                    END IF;
                END LOOP;
                SELECT * INTO STRICT folded FROM {namespace}.serverware_policy_authority_counted_branch(
                    index_identity,prefix,before_children,before_child_counts);
                before_digests[parent_number] := folded.node_digest;
                before_counts[parent_number] := folded.subtree_count;
                IF prefix <> '' THEN
                    slot := pg_catalog.array_position(requested_prefixes,prefix);
                    IF slot IS NULL
                        OR cached_digests[slot] IS DISTINCT FROM CASE WHEN folded.subtree_count > 0 THEN folded.node_digest ELSE NULL END
                        OR cached_counts[slot] IS DISTINCT FROM CASE WHEN folded.subtree_count > 0 THEN folded.subtree_count ELSE NULL END
                    THEN RAISE EXCEPTION 'counted path opened cache differs from reconstructed BEFORE'; END IF;
                END IF;
                SELECT * INTO STRICT folded FROM {namespace}.serverware_policy_authority_counted_branch(
                    index_identity,prefix,after_children,after_child_counts);
                after_digests[parent_number] := folded.node_digest;
                after_counts[parent_number] := folded.subtree_count;
            END LOOP;
            IF root_number IS NULL
                OR before_digests[root_number] COLLATE "C" IS DISTINCT FROM current_head.root_digest COLLATE "C"
                OR before_counts[root_number] IS DISTINCT FROM current_head.leaf_count
            THEN RAISE EXCEPTION 'counted path reconstructed BEFORE differs from locked head'; END IF;
            IF NOT old_member AND NOT new_member THEN
                -- Still performed both genuine root folds and identity lookup.
                RETURN;
            END IF;
            IF current_head.index_revision = 9223372036854775807 THEN
                RAISE EXCEPTION 'counted path member revision overflows signed64';
            END IF;
            next_revision := current_head.index_revision+1;
            IF after_counts[root_number] IS DISTINCT FROM current_head.leaf_count
                - CASE WHEN old_member THEN 1 ELSE 0 END + CASE WHEN new_member THEN 1 ELSE 0 END
            THEN RAISE EXCEPTION 'counted path member count delta changed'; END IF;

            -- First persistent write: all bounded acquisition and both genuine
            -- folds have succeeded. Remove the old key before a partition move
            -- inserts the same unique BusinessKey commitment at its new key.
            IF old_member THEN
                DELETE FROM {namespace}.policy_authority_counted_index_leaves AS l
                WHERE l.index_id COLLATE "C" = index_identity COLLATE "C" AND l.index_key COLLATE "C" = old_key COLLATE "C";
                IF NOT FOUND THEN RAISE EXCEPTION 'counted path OLD leaf disappeared before publication'; END IF;
            END IF;
            IF new_member THEN
                INSERT INTO {namespace}.policy_authority_counted_index_leaves(
                    index_id,projection_digest,index_key,primary_id,primary_key_digest,primary_row_digest,index_revision)
                VALUES(index_identity,source_projection,new_key,event_id,identity_digest,new_row_digest,next_revision);
            END IF;
            FOREACH target IN ARRAY target_keys LOOP
                IF new_member AND target COLLATE "C" = new_key COLLATE "C" THEN
                    INSERT INTO {namespace}.policy_authority_counted_index_nodes(
                        index_id,projection_digest,depth,path_prefix,node_digest,subtree_count,index_revision)
                    VALUES(index_identity,source_projection,160,target,new_leaf_digest,1,next_revision)
                    ON CONFLICT (index_id,depth,path_prefix) DO UPDATE
                    SET projection_digest=EXCLUDED.projection_digest,node_digest=EXCLUDED.node_digest,
                        subtree_count=EXCLUDED.subtree_count,index_revision=EXCLUDED.index_revision;
                ELSE
                    DELETE FROM {namespace}.policy_authority_counted_index_nodes AS n
                    WHERE n.index_id COLLATE "C" = index_identity COLLATE "C" AND n.depth=160 AND n.path_prefix COLLATE "C" = target COLLATE "C";
                END IF;
            END LOOP;
            FOR parent_number IN 1..opened_count LOOP
                prefix := opened[parent_number];
                IF prefix = '' THEN CONTINUE; END IF;
                IF after_counts[parent_number] > 0 THEN
                    INSERT INTO {namespace}.policy_authority_counted_index_nodes(
                        index_id,projection_digest,depth,path_prefix,node_digest,subtree_count,index_revision)
                    VALUES(index_identity,source_projection,pg_catalog.char_length(prefix),prefix,
                        after_digests[parent_number],after_counts[parent_number],next_revision)
                    ON CONFLICT (index_id,depth,path_prefix) DO UPDATE
                    SET projection_digest=EXCLUDED.projection_digest,node_digest=EXCLUDED.node_digest,
                        subtree_count=EXCLUDED.subtree_count,index_revision=EXCLUDED.index_revision;
                ELSE
                    DELETE FROM {namespace}.policy_authority_counted_index_nodes AS n
                    WHERE n.index_id COLLATE "C" = index_identity COLLATE "C"
                      AND n.depth=pg_catalog.char_length(prefix) AND n.path_prefix COLLATE "C" = prefix COLLATE "C";
                END IF;
            END LOOP;
            UPDATE {namespace}.policy_authority_counted_index_heads AS h
            SET index_revision=next_revision,root_digest=after_digests[root_number],leaf_count=after_counts[root_number]
            WHERE h.index_id COLLATE "C" = index_identity COLLATE "C"
              AND h.table_name COLLATE "C" = source_table COLLATE "C"
              AND h.counted_profile COLLATE "C" = '{contract.PROFILE}' COLLATE "C"
              AND h.projection_digest COLLATE "C" = source_projection COLLATE "C"
              AND h.projection_manifest_digest COLLATE "C" = '{manifest}' COLLATE "C"
              AND h.index_revision=current_head.index_revision
              AND h.root_digest COLLATE "C" = current_head.root_digest COLLATE "C" AND h.leaf_count=current_head.leaf_count;
            IF NOT FOUND THEN RAISE EXCEPTION 'counted path head compare-and-set failed'; END IF;
        END;
        $counted_path$
        """,)
