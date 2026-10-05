"""Fixed challenge maintenance effects inside an admitted stream transaction.

These are fragments, not a callable function, installer, grant or execution
authority. The owning SECURITY DEFINER executor must acquire original immutable
custody, verify the parent, step chain and six-phase order, hold the complete
root reservation, and finish its marker in ONE transaction. It must also admit
the installed functions, roles, schema and business triggers independently.

The owner assigns the cme_* input locals below from that custody. One row call
applies only a genuine replay-derived UPDATE/DELETE, with the original primary
descriptor on either side. Phase observations compare all nine actual counted
heads. They do not prove candidate completeness, root currentness outside the
transaction, or permission to invoke this SQL. Any failure aborts the outer
transaction; there is no retry, exception recovery, commit, GUC or clock renewal.
Wire parsing/SQL/trigger resources are not Python shared-work measurements.
"""
from __future__ import annotations

from serverware import authority_challenge_id as challenge_id
from serverware import authority_contract as authority
from serverware import authority_index_projection as projection
from serverware import authority_primary_contract as primary
from serverware.authority_store import mutation_sql, primary_tree_sql
from serverware.authority_store.revocation_retained_sql import _closed, _literal
from serverware.authority_store.wire_json_sql import WIRE_JSON_MAX_DEPTH, WIRE_JSON_MAX_NODES


TABLE = "webauthn_challenges"
OPERATION = "webauthn.challenge.maintain"
MAX_MUTATION_BYTES = 4 * 1024 * 1024
PHASE_ORDINALS = (0, 1, 2, 4, 5, 6)


def _source():
    spec = authority.operation_spec(OPERATION)
    templates = tuple(spec["mutationTemplates"])
    ids = projection.index_ids_for_table(TABLE)
    if (primary.PRIMARY_KEY_COLUMNS[TABLE] != ("id",)
            or tuple(spec["businessWrites"]) != (TABLE,)
            or len(templates) != 2 or len(ids) != 9 or ids != tuple(sorted(set(ids)))
            or {item["mutation"] for item in templates} != {"UPDATE", "DELETE"}
            or any(item["operation"] != OPERATION or item["table"] != TABLE
                or item["predicate"] != "exact-primary-key-and-full-row-cas-v1"
                or item["cardinality"] != 1 for item in templates)
            or spec["maximumMutations"] != 256):
        raise ValueError("challenge maintenance effect source inventory changed")
    return ids, {item["mutation"]: item["templateId"] for item in templates}


def declarations_sql() -> str:
    """Fixed inputs and scratch; generic mutation locals live in a nested block.

    Inputs: integer phase/row ordinals, original canonical mutation text,
    admitted primary4 before/after objects, admitted phase {primaryRoot,
    indexHeads} before/after objects, and the unchanged epoch-nanosecond deadline.
    """
    return """
        cme_phase_ordinal integer; cme_row_ordinal integer;
        cme_mutation_json text; cme_deadline_epoch_ns bigint;
        cme_primary_before jsonb; cme_primary_after jsonb;
        cme_phase_before jsonb; cme_phase_after jsonb;
        cme_actual_primary jsonb; cme_actual_heads jsonb; cme_actual_phase jsonb;
        cme_root record; cme_head record; cme_measured record; cme_rendered record;
        cme_count integer; cme_position integer; cme_ids text[];
        cme_empty text; cme_canonical text; cme_projection text;
    """


def _live_sql():
    return """
        IF cme_phase_ordinal IS NULL OR cme_phase_ordinal NOT IN (0, 1, 2, 4, 5, 6)
            OR cme_deadline_epoch_ns IS NULL OR cme_deadline_epoch_ns <= 0
            OR pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000000)
                >= cme_deadline_epoch_ns
        THEN RAISE EXCEPTION 'challenge maintenance original phase/deadline differs'; END IF;
    """


def _observe_primary_sql(namespace):
    manifest = primary.source_query_manifest_digest()
    return f"""
        cme_count := 0;
        FOR cme_root IN
            SELECT table_name, manifest_digest, tree_depth, tree_radix,
                root_revision, root_digest, leaf_count
            FROM {namespace}.policy_authority_authenticated_table_roots
            WHERE table_name COLLATE "C" = '{TABLE}' COLLATE "C"
            LIMIT 2 FOR UPDATE
        LOOP
            cme_count := cme_count + 1;
            IF cme_count <> 1
                OR cme_root.table_name COLLATE "C" IS DISTINCT FROM '{TABLE}' COLLATE "C"
                OR cme_root.manifest_digest COLLATE "C" IS DISTINCT FROM {_literal(manifest)} COLLATE "C"
                OR cme_root.tree_depth IS DISTINCT FROM {authority.TREE_DEPTH}
                OR cme_root.tree_radix IS DISTINCT FROM {authority.TREE_RADIX}
                OR cme_root.root_revision IS NULL OR cme_root.root_revision < 0
                OR cme_root.leaf_count IS NULL OR cme_root.leaf_count < 0
                OR cme_root.root_digest IS NULL OR pg_catalog.octet_length(cme_root.root_digest) <> 71
                OR cme_root.root_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
                OR (cme_root.root_revision = 0 AND cme_root.leaf_count <> 0)
            THEN RAISE EXCEPTION 'challenge maintenance primary source differs'; END IF;
            cme_empty := {namespace}.serverware_policy_authority_authenticated_empty(0);
            IF (cme_root.leaf_count = 0) IS DISTINCT FROM (cme_root.root_digest = cme_empty)
            THEN RAISE EXCEPTION 'challenge maintenance primary empty convention differs'; END IF;
            cme_actual_primary := pg_catalog.jsonb_build_object(
                'table', cme_root.table_name, 'rootRevision', cme_root.root_revision,
                'rootDigest', cme_root.root_digest, 'leafCount', cme_root.leaf_count);
        END LOOP;
        IF cme_count <> 1 THEN RAISE EXCEPTION 'challenge maintenance primary is absent'; END IF;
    """


def _wire_mutation_sql(namespace):
    return f"""
        SELECT * INTO STRICT cme_measured FROM {namespace}.serverware_policy_authority_wire_walk(
            mutation, {WIRE_JSON_MAX_DEPTH}, {WIRE_JSON_MAX_NODES}, {MAX_MUTATION_BYTES}, FALSE);
        SELECT * INTO STRICT cme_rendered FROM {namespace}.serverware_policy_authority_wire_walk(
            mutation, {WIRE_JSON_MAX_DEPTH}, cme_measured.visited_nodes, cme_measured.emitted_bytes, TRUE);
        IF cme_rendered.visited_nodes IS DISTINCT FROM cme_measured.visited_nodes
            OR cme_rendered.emitted_bytes IS DISTINCT FROM cme_measured.emitted_bytes
            OR pg_catalog.octet_length(cme_rendered.rendered) IS DISTINCT FROM cme_measured.emitted_bytes
        THEN RAISE EXCEPTION 'challenge maintenance wire measurement changed'; END IF;
        cme_canonical := cme_rendered.rendered;
        IF cme_canonical COLLATE "C" IS DISTINCT FROM cme_mutation_json COLLATE "C"
        THEN RAISE EXCEPTION 'challenge maintenance mutation is not canonical'; END IF;
    """


def row_body_sql(namespace: str) -> str:
    """One fixed OLD-row CAS, retaining real primary/count trigger effects.

    The genuine shared mutation helper contains its existing INSERT branch;
    the preceding closed source template/phase admission makes it unreachable.
    No independently copied mutation implementation or direct root write exists.
    """
    namespace = primary_tree_sql._namespace(namespace)
    _ids, templates = _source()
    return f"""
        DECLARE
            mutation jsonb; key_columns jsonb; current_row jsonb; post_row jsonb;
            key_names text[]; supplied_key_names text[]; key_predicate text;
            update_columns text; matched_count bigint;
        BEGIN
            {_live_sql()}
            IF cme_row_ordinal IS NULL OR cme_row_ordinal NOT BETWEEN 0 AND 255
                OR cme_mutation_json IS NULL
                OR pg_catalog.octet_length(cme_mutation_json) NOT BETWEEN 2 AND {MAX_MUTATION_BYTES}
            THEN RAISE EXCEPTION 'challenge maintenance row framing differs'; END IF;
            mutation := cme_mutation_json::pg_catalog.jsonb;
            {_wire_mutation_sql(namespace)}
            IF NOT {mutation_sql.closed_record_sql('mutation')}
                OR mutation->'table' IS DISTINCT FROM '"{TABLE}"'::pg_catalog.jsonb
                OR NOT {_closed("mutation->'key'", ('id',))}
                OR pg_catalog.jsonb_typeof(mutation->'key'->'id') IS DISTINCT FROM 'string'
                OR NOT ((pg_catalog.octet_length(mutation->'key'->>'id') = 36
                        AND mutation->'key'->>'id' COLLATE "C" ~ '^{challenge_id.UUID_PATTERN}$')
                    OR (pg_catalog.octet_length(mutation->'key'->>'id') = 71
                        AND mutation->'key'->>'id' COLLATE "C" ~ '^{challenge_id.SHA_PATTERN}$'))
                OR pg_catalog.jsonb_typeof(mutation->'expectedRow') IS DISTINCT FROM 'object'
                OR mutation->'expectedRow'->'id' IS DISTINCT FROM mutation->'key'->'id'
                OR mutation->>'keyDigest' IS DISTINCT FROM
                    {namespace}.serverware_policy_authority_domain_digest(
                        'serverware.policyAuthorityBusinessKey/v1', '{TABLE}',
                        {namespace}.serverware_policy_authority_wire_json(mutation->'key'))
            THEN RAISE EXCEPTION 'challenge maintenance mutation identity differs'; END IF;
            IF cme_phase_ordinal IN (0, 4) THEN
                IF mutation->'operation' IS DISTINCT FROM '"UPDATE"'::pg_catalog.jsonb
                    OR mutation->>'templateId' IS DISTINCT FROM {_literal(templates['UPDATE'])}
                    OR pg_catalog.jsonb_typeof(mutation->'row') IS DISTINCT FROM 'object'
                    OR mutation->'expectedRow'->'used_at' IS DISTINCT FROM 'null'::pg_catalog.jsonb
                    OR pg_catalog.jsonb_typeof(mutation->'row'->'used_at') IS DISTINCT FROM 'string'
                    OR (mutation->'row' - 'used_at') IS DISTINCT FROM (mutation->'expectedRow' - 'used_at')
                THEN RAISE EXCEPTION 'challenge maintenance expiry is not its exact UPDATE'; END IF;
            ELSE
                IF mutation->'operation' IS DISTINCT FROM '"DELETE"'::pg_catalog.jsonb
                    OR mutation->>'templateId' IS DISTINCT FROM {_literal(templates['DELETE'])}
                    OR mutation->'row' IS DISTINCT FROM 'null'::pg_catalog.jsonb
                    OR mutation->'expectedRow'->'retention_reference_mask' IS DISTINCT FROM '0'::pg_catalog.jsonb
                THEN RAISE EXCEPTION 'challenge maintenance prune is not its exact DELETE'; END IF;
            END IF;
            {_observe_primary_sql(namespace)}
            IF cme_actual_primary IS DISTINCT FROM cme_primary_before
            THEN RAISE EXCEPTION 'challenge maintenance primary before differs'; END IF;
            {_live_sql()}
            key_columns := '["id"]'::pg_catalog.jsonb;
            {mutation_sql.apply_mutation_sql(namespace)}
            {_observe_primary_sql(namespace)}
            IF cme_actual_primary IS DISTINCT FROM cme_primary_after
            THEN RAISE EXCEPTION 'challenge maintenance primary after differs'; END IF;
            {_live_sql()}
        END;
    """


def phase_roots_body_sql(namespace: str, *, stage: str) -> str:
    """Lock/read exact primary plus all nine heads at a source-selected edge.

    stage selects generated SQL only; there is no runtime choice or alternate
    table/profile inventory. Empty phases still require both observations.
    """
    namespace = primary_tree_sql._namespace(namespace)
    if type(stage) is not str or stage not in ("before", "after"):
        raise ValueError("challenge maintenance phase edge is not source fixed")
    ids, _templates = _source()
    source_ids = ", ".join(_literal(identity) for identity in ids)
    projection_cases = "\n".join(
        f"WHEN {_literal(identity)} THEN {_literal(projection.profile_for(identity).projection_digest)}"
        for identity in ids)
    projection_manifest = projection.projection_manifest_digest()
    return f"""
        {_live_sql()}
        {_observe_primary_sql(namespace)}
        cme_ids := ARRAY[{source_ids}]::text[];
        cme_actual_heads := '[]'::pg_catalog.jsonb;
        cme_position := 0;
        FOR cme_head IN
            SELECT index_id, table_name, counted_profile, projection_digest,
                projection_manifest_digest, index_revision, root_digest, leaf_count
            FROM {namespace}.policy_authority_counted_index_heads
            WHERE index_id COLLATE "C" IN ({source_ids})
            ORDER BY index_id COLLATE "C" LIMIT 10 FOR UPDATE
        LOOP
            cme_position := cme_position + 1;
            cme_projection := CASE cme_head.index_id COLLATE "C"
                {projection_cases}
                ELSE NULL END;
            IF cme_position > 9
                OR cme_head.index_id COLLATE "C" IS DISTINCT FROM cme_ids[cme_position] COLLATE "C"
                OR cme_head.table_name COLLATE "C" IS DISTINCT FROM '{TABLE}' COLLATE "C"
                OR cme_head.counted_profile COLLATE "C" IS DISTINCT FROM {_literal(projection.COUNTED_PROFILE)} COLLATE "C"
                OR cme_head.projection_digest COLLATE "C" IS DISTINCT FROM cme_projection COLLATE "C"
                OR cme_head.projection_manifest_digest COLLATE "C" IS DISTINCT FROM {_literal(projection_manifest)} COLLATE "C"
                OR cme_head.index_revision IS NULL OR cme_head.index_revision < 0
                OR cme_head.leaf_count IS NULL OR cme_head.leaf_count < 0
                OR cme_head.leaf_count > (cme_actual_primary->>'leafCount')::bigint
                OR cme_head.root_digest IS NULL OR pg_catalog.octet_length(cme_head.root_digest) <> 71
                OR cme_head.root_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
                OR (cme_head.index_revision = 0 AND cme_head.leaf_count <> 0)
            THEN RAISE EXCEPTION 'challenge maintenance counted head source differs'; END IF;
            cme_empty := {namespace}.serverware_policy_authority_counted_empty(cme_head.index_id, '');
            IF (cme_head.leaf_count = 0) IS DISTINCT FROM (cme_head.root_digest = cme_empty)
            THEN RAISE EXCEPTION 'challenge maintenance counted empty convention differs'; END IF;
            cme_actual_heads := cme_actual_heads || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
                'indexId', cme_head.index_id, 'table', cme_head.table_name,
                'countedProfile', cme_head.counted_profile, 'projectionDigest', cme_head.projection_digest,
                'projectionManifestDigest', cme_head.projection_manifest_digest,
                'indexRevision', cme_head.index_revision, 'rootDigest', cme_head.root_digest,
                'rootCount', cme_head.leaf_count));
        END LOOP;
        IF cme_position <> 9 THEN RAISE EXCEPTION 'challenge maintenance counted inventory is incomplete'; END IF;
        cme_actual_phase := pg_catalog.jsonb_build_object(
            'primaryRoot', cme_actual_primary, 'indexHeads', cme_actual_heads);
        IF cme_actual_phase IS DISTINCT FROM cme_phase_{stage}
        THEN RAISE EXCEPTION 'challenge maintenance phase {stage} differs'; END IF;
        {_live_sql()}
    """
