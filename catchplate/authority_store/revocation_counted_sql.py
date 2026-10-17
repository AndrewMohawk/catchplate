"""Private fresh-apply counted-head checks for an independently admitted v4 plan.

The caller must first replay the original signed record with independent trust
inputs, run the retained-byte binder, validate the primary transition and lock
every required primary root in source-sorted order. These fragments then run in
that same writer transaction, around the actual mutation/maintenance statements.
They must never run in committed historical replay. They install no entrypoint,
admit no capability and replace neither primary CAS nor complete proof checking.

Only a namespace is supplied to the renderers. Index inventories come from the
six source roles and every profile of each actually mutated source table. SQL
projection/encoding/hashing is outside Python H/B/N accounting. Phase locals are
call-order correctness guards, not transferable successful-verification tokens.
"""
from __future__ import annotations

import textwrap

from catchplate import authority_complete_query as complete
from catchplate import authority_contract as authority
from catchplate import authority_index_contract as counted
from catchplate import authority_index_projection as projection
from catchplate import authority_revocation_bundle_contract as bundle
from catchplate.authority_store.mutation_sql import _schema_name
from catchplate.authority_store.revocation_retained_sql import _closed, _literal


def _array(values):
    return "ARRAY[" + ", ".join(_literal(value) for value in values) + "]::text[]"


def _counters(expression, fields):
    # Expressions/fields are fixed below, never caller-provided SQL.
    return f"""
        FOREACH rvc_field IN ARRAY {_array(fields)} LOOP
            IF pg_catalog.jsonb_typeof({expression}->rvc_field) IS DISTINCT FROM 'number'
                OR ({expression}->>rvc_field) COLLATE "C" !~ '^(0|[1-9][0-9]*)$'
                OR pg_catalog.length({expression}->>rvc_field) > 19
            THEN RAISE EXCEPTION 'revocation counted counter type is invalid'; END IF;
            IF ({expression}->>rvc_field)::numeric NOT BETWEEN 0 AND 9223372036854775807
            THEN RAISE EXCEPTION 'revocation counted counter bound is invalid'; END IF;
        END LOOP;
    """


def revocation_counted_declarations_sql() -> str:
    """Locals alongside locked ``planner`` and bound rv_payload/transition/primary.

    Preparation captures rvc_before_heads/rvc_after_heads and source-sorted
    rvc_index_ids/rvc_write_ids. The before/after fragments expose their actual
    compact observations as rvc_actual_before_heads/rvc_actual_after_heads.
    No legacy rt_* or retained rv_* variable is overwritten.
    """
    return """
        rvc_phase integer := 0;
        rvc_inputs pg_catalog.jsonb;
        rvc_arguments pg_catalog.jsonb;
        rvc_mutations pg_catalog.jsonb;
        rvc_before_heads pg_catalog.jsonb;
        rvc_after_heads pg_catalog.jsonb;
        rvc_actual_before_heads pg_catalog.jsonb;
        rvc_actual_after_heads pg_catalog.jsonb;
        rvc_descriptors pg_catalog.jsonb;
        rvc_query pg_catalog.jsonb;
        rvc_selector pg_catalog.jsonb;
        rvc_mutation pg_catalog.jsonb;
        rvc_frontier pg_catalog.jsonb;
        rvc_head pg_catalog.jsonb;
        rvc_before pg_catalog.jsonb;
        rvc_after pg_catalog.jsonb;
        rvc_primary_head pg_catalog.jsonb;
        rvc_hint pg_catalog.jsonb;
        rvc_scalar pg_catalog.jsonb;
        rvc_roles text[];
        rvc_read_ids text[];
        rvc_write_ids text[];
        rvc_index_ids text[];
        rvc_mutated_tables text[];
        rvc_addresses text[];
        rvc_previous text;
        rvc_field text;
        rvc_side text;
        rvc_role text;
        rvc_index text;
        rvc_table text;
        rvc_projection text;
        rvc_empty text;
        rvc_hint_name text;
        rvc_address text;
        rvc_maximum integer;
        rvc_position integer;
        rvc_matches integer;
        rvc_old_count bigint;
        rvc_new_count bigint;
        rvc_revision_delta bigint;
        rvc_count_delta bigint;
        rvc_candidate record;
        rvc_source_head record;
    """


def prepare_revocation_counted_transition_sql(namespace: str) -> str:
    """Bind the exact role/write union and project real OLD/NEW membership.

    No live heads are read here. The caller has already admitted bounded raw
    v4 evidence and locked/validated primary roots; this repeats only the
    counted consumer's exact source/inventory/lifecycle and delta obligations.
    The captured vectors, not a subsequently changed rv_transition, are used
    by both live-state fragments. Repeated or out-of-order calls are denied.
    """
    _schema_name(namespace)
    spec = authority.operation_spec(complete.OPERATION)
    roles = tuple(complete._role(complete.OPERATION, name) for name in complete.ROLES)
    read_ids = tuple(sorted({role.index_id for role in roles}))
    write_tables = tuple(spec["writes"])
    possible_ids = tuple(sorted(set(read_ids) | {
        index_id for table in write_tables for index_id in projection.index_ids_for_table(table)}))
    profile_values = ",\n".join("(" + ", ".join(_literal(value) for value in (
        index_id, projection.profile_for(index_id).table,
        projection.profile_for(index_id).projection_digest)) + ")" for index_id in possible_ids)
    table_cases = "\n".join(f"WHEN {_literal(table)} THEN {_array(projection.index_ids_for_table(table))}"
                            for table in write_tables)
    template_values = ",\n".join("(" + ", ".join(_literal(template[field])
        for field in ("templateId", "table", "mutation")) + ")" for template in spec["mutationTemplates"])
    role_cases = []
    for role in roles:
        if role.name == "global_registration_challenges":
            selector = "pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_array('expires_after_us', rvc_inputs->'cutoffUs'))"
        elif role.name == "pending_trust_publications":
            selector = "pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_array('status', 'pending'))"
        else:
            pairs = ["pg_catalog.jsonb_build_array('credential_record_id', rvc_arguments->'record_id')"]
            if role.status is not None:
                pairs.append("pg_catalog.jsonb_build_array('status', " + _literal(role.status) + ")")
            selector = "pg_catalog.jsonb_build_array(" + ", ".join(pairs) + ")"
        maximum = ("1" if role.hint_field is None else
                   "GREATEST(1, pg_catalog.jsonb_array_length(rvc_arguments->" + _literal(role.hint_field) + "))")
        role_cases.append(f"""WHEN {_literal(role.name)} THEN
            rvc_index := {_literal(role.index_id)};
            rvc_selector := {selector}; rvc_maximum := {maximum};""")
    role_sql = "\n".join(role_cases)
    return textwrap.dedent(f"""
        IF rvc_phase IS DISTINCT FROM 0
        THEN RAISE EXCEPTION 'revocation counted prepare phase is invalid'; END IF;
        rvc_phase := -1;
        IF planner.plan_protocol IS DISTINCT FROM 'revocation-v4'
            OR planner.status IS DISTINCT FROM 'planned'
            OR planner.operation IS DISTINCT FROM {_literal(complete.OPERATION)}
            OR planner.source_revision IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
            OR rv_transition IS DISTINCT FROM rv_payload->'rootTransition'
            OR rv_primary IS DISTINCT FROM rv_transition->'primaryTransition'
            OR rv_transition->>'operation' IS DISTINCT FROM planner.operation
            OR rv_transition->>'requestDigest' IS DISTINCT FROM planner.request_digest
            OR rv_transition->>'countedProfile' IS DISTINCT FROM {_literal(counted.PROFILE)}
            OR rv_transition->>'projectionManifestDigest' IS DISTINCT FROM {_literal(projection.projection_manifest_digest())}
            OR NOT {_closed("rv_payload->'revocationProofBundle'", bundle.BUNDLE_FIELDS)}
            OR rv_payload->'revocationProofBundle'->>'schema' IS DISTINCT FROM {_literal(bundle.BUNDLE_SCHEMA)}
            OR rv_payload->'revocationProofBundle'->>'profile' IS DISTINCT FROM {_literal(bundle.BUNDLE_PROFILE)}
            OR rv_payload->'revocationProofBundle'->>'sourceRevision' IS DISTINCT FROM planner.source_revision
        THEN RAISE EXCEPTION 'revocation counted source binding changed'; END IF;
        rvc_inputs := rv_payload->'revocationProofBundle'->'inputs';
        IF NOT {_closed('rvc_inputs', bundle.INPUT_FIELDS)}
            OR rvc_inputs->>'operation' IS DISTINCT FROM planner.operation
            OR rvc_inputs->>'requestDigest' IS DISTINCT FROM planner.request_digest
            OR rvc_inputs->'arguments' IS DISTINCT FROM rv_payload->'typedRequest'->'arguments'
            OR rvc_inputs->'cutoffUs' IS DISTINCT FROM rv_transition->'cutoffUs'
            OR rvc_inputs->'assertionBinding' IS DISTINCT FROM rv_transition->'assertionBinding'
            OR rvc_inputs->'businessBeforeRoots' IS DISTINCT FROM rv_primary->'businessBeforeRoots'
            OR rvc_inputs->'authorizationBeforeRoots' IS DISTINCT FROM rv_primary->'authorizationBeforeRoots'
            OR rvc_inputs->'selectedRows' IS DISTINCT FROM rv_payload->'selectedBusinessRows'
            OR rvc_inputs->'beforeProofs' IS DISTINCT FROM rv_payload->'queryMultiproofs'
            OR rvc_inputs->'mutations' IS DISTINCT FROM rv_payload->'mutationPlan'
            OR rvc_inputs->'countedBeforeHeads' IS DISTINCT FROM rv_transition->'indexBeforeHeads'
        THEN RAISE EXCEPTION 'revocation counted proof input binding changed'; END IF;
        rvc_arguments := rvc_inputs->'arguments';
        IF pg_catalog.jsonb_typeof(rvc_arguments) IS DISTINCT FROM 'object'
            OR rvc_arguments->>'source' IS DISTINCT FROM 'explicit'
            OR pg_catalog.jsonb_typeof(rvc_arguments->'record_id') IS DISTINCT FROM 'string'
            OR pg_catalog.octet_length(rvc_arguments->>'record_id') NOT BETWEEN 1 AND {complete.MAX_SOURCE_ID_BYTES}
        THEN RAISE EXCEPTION 'revocation counted role arguments are invalid'; END IF;
        FOREACH rvc_hint_name IN ARRAY {_array(complete._HINT_FIELDS)} LOOP
            rvc_hint := rvc_arguments->rvc_hint_name;
            IF pg_catalog.jsonb_typeof(rvc_hint) IS DISTINCT FROM 'array'
            THEN RAISE EXCEPTION 'revocation counted role hints are invalid'; END IF;
            IF pg_catalog.jsonb_array_length(rvc_hint) > {complete.CASCADE_MAX}
            THEN RAISE EXCEPTION 'revocation counted role hints exceed their source bound'; END IF;
            rvc_previous := NULL;
            FOR rvc_scalar IN SELECT value FROM pg_catalog.jsonb_array_elements(rvc_hint) LOOP
                IF pg_catalog.jsonb_typeof(rvc_scalar) IS DISTINCT FROM 'string'
                    OR pg_catalog.octet_length(rvc_scalar #>> '{{}}') NOT BETWEEN 1 AND {complete.MAX_SOURCE_ID_BYTES}
                    OR (rvc_previous IS NOT NULL AND (rvc_scalar #>> '{{}}') COLLATE "C" <= rvc_previous COLLATE "C")
                THEN RAISE EXCEPTION 'revocation counted role hints are not sorted unique IDs'; END IF;
                rvc_previous := rvc_scalar #>> '{{}}';
            END LOOP;
        END LOOP;
        IF pg_catalog.jsonb_typeof(rvc_inputs->'queries') IS DISTINCT FROM 'array'
        THEN RAISE EXCEPTION 'revocation counted role inventory is invalid'; END IF;
        IF pg_catalog.jsonb_array_length(rvc_inputs->'queries') <> {len(roles)}
        THEN RAISE EXCEPTION 'revocation counted role inventory is invalid'; END IF;
        rvc_roles := ARRAY[]::text[]; rvc_read_ids := ARRAY[]::text[];
        FOR rvc_query IN SELECT value FROM pg_catalog.jsonb_array_elements(rvc_inputs->'queries') LOOP
            IF NOT {_closed('rvc_query', bundle._QUERY_FIELDS)}
                OR rvc_query->>'operation' IS DISTINCT FROM planner.operation
                OR pg_catalog.jsonb_typeof(rvc_query->'role') IS DISTINCT FROM 'string'
            THEN RAISE EXCEPTION 'revocation counted role declaration is invalid'; END IF;
            rvc_role := rvc_query->>'role';
            IF rvc_role = ANY(rvc_roles)
            THEN RAISE EXCEPTION 'revocation counted role is duplicated'; END IF;
            CASE rvc_role COLLATE "C"
                {role_sql}
                ELSE RAISE EXCEPTION 'revocation counted role is not source declared';
            END CASE;
            IF rvc_query->'selectorItems' IS DISTINCT FROM rvc_selector
                OR pg_catalog.jsonb_typeof(rvc_query->'maximumRows') IS DISTINCT FROM 'number'
                OR rvc_query->>'maximumRows' IS DISTINCT FROM rvc_maximum::text
            THEN RAISE EXCEPTION 'revocation counted role selector or bound changed'; END IF;
            rvc_roles := pg_catalog.array_append(rvc_roles, rvc_role);
            rvc_read_ids := pg_catalog.array_append(rvc_read_ids, rvc_index);
        END LOOP;
        rvc_mutations := rvc_inputs->'mutations';
        IF pg_catalog.jsonb_typeof(rvc_mutations) IS DISTINCT FROM 'array'
        THEN RAISE EXCEPTION 'revocation counted mutations are not an array'; END IF;
        IF pg_catalog.jsonb_array_length(rvc_mutations) > {spec['maximumMutations']}
        THEN RAISE EXCEPTION 'revocation counted mutation count exceeds source'; END IF;
        rvc_mutated_tables := ARRAY[]::text[]; rvc_addresses := ARRAY[]::text[];
        FOR rvc_mutation IN SELECT value FROM pg_catalog.jsonb_array_elements(rvc_mutations) LOOP
            IF NOT {_closed('rvc_mutation', bundle._MUTATION_FIELDS)}
                OR pg_catalog.jsonb_typeof(rvc_mutation->'table') IS DISTINCT FROM 'string'
                OR pg_catalog.jsonb_typeof(rvc_mutation->'operation') IS DISTINCT FROM 'string'
                OR pg_catalog.jsonb_typeof(rvc_mutation->'templateId') IS DISTINCT FROM 'string'
                OR pg_catalog.jsonb_typeof(rvc_mutation->'keyDigest') IS DISTINCT FROM 'string'
                OR (rvc_mutation->>'keyDigest') COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
                OR pg_catalog.jsonb_typeof(rvc_mutation->'key') IS DISTINCT FROM 'object'
            THEN RAISE EXCEPTION 'revocation counted mutation is not closed'; END IF;
            IF NOT EXISTS (SELECT 1 FROM (VALUES {template_values}) AS source(template_id, table_name, opcode)
                WHERE source.template_id COLLATE "C" = (rvc_mutation->>'templateId') COLLATE "C"
                    AND source.table_name COLLATE "C" = (rvc_mutation->>'table') COLLATE "C"
                    AND source.opcode COLLATE "C" = (rvc_mutation->>'operation') COLLATE "C")
            THEN RAISE EXCEPTION 'revocation counted mutation template is not source declared'; END IF;
            IF (rvc_mutation->>'operation' = 'INSERT' AND
                    (rvc_mutation->'expectedRow' IS DISTINCT FROM 'null'::jsonb
                     OR pg_catalog.jsonb_typeof(rvc_mutation->'row') IS DISTINCT FROM 'object'))
                OR (rvc_mutation->>'operation' = 'UPDATE' AND
                    (pg_catalog.jsonb_typeof(rvc_mutation->'expectedRow') IS DISTINCT FROM 'object'
                     OR pg_catalog.jsonb_typeof(rvc_mutation->'row') IS DISTINCT FROM 'object'))
                OR (rvc_mutation->>'operation' = 'DELETE' AND
                    (pg_catalog.jsonb_typeof(rvc_mutation->'expectedRow') IS DISTINCT FROM 'object'
                     OR rvc_mutation->'row' IS DISTINCT FROM 'null'::jsonb))
            THEN RAISE EXCEPTION 'revocation counted mutation lifecycle is invalid'; END IF;
            rvc_table := rvc_mutation->>'table';
            rvc_address := rvc_table || ':' || (rvc_mutation->>'keyDigest');
            IF rvc_address = ANY(rvc_addresses)
            THEN RAISE EXCEPTION 'revocation counted mutation address is duplicated'; END IF;
            rvc_addresses := pg_catalog.array_append(rvc_addresses, rvc_address);
            rvc_mutated_tables := pg_catalog.array_append(rvc_mutated_tables, rvc_table);
            IF rvc_table = ANY({_array(tuple(table for table in write_tables if projection.index_ids_for_table(table)))}) THEN
                IF NOT {_closed("rvc_mutation->'key'", ('id',))}
                    OR pg_catalog.jsonb_typeof(rvc_mutation->'key'->'id') IS DISTINCT FROM 'string'
                    OR (rvc_mutation->'expectedRow' <> 'null'::jsonb AND
                        rvc_mutation->'expectedRow'->'id' IS DISTINCT FROM rvc_mutation->'key'->'id')
                    OR (rvc_mutation->'row' <> 'null'::jsonb AND
                        rvc_mutation->'row'->'id' IS DISTINCT FROM rvc_mutation->'key'->'id')
                THEN RAISE EXCEPTION 'revocation counted mutation primary ID changed'; END IF;
            END IF;
        END LOOP;
        rvc_write_ids := ARRAY[]::text[];
        FOREACH rvc_table IN ARRAY rvc_mutated_tables LOOP
            rvc_write_ids := rvc_write_ids || CASE rvc_table COLLATE "C"
                {table_cases}
                ELSE ARRAY[]::text[] END;
        END LOOP;
        SELECT COALESCE(pg_catalog.array_agg(value ORDER BY value COLLATE "C"), ARRAY[]::text[])
            INTO rvc_write_ids FROM (SELECT DISTINCT value COLLATE "C" AS value
                FROM pg_catalog.unnest(rvc_write_ids) AS value) AS source;
        SELECT pg_catalog.array_agg(value ORDER BY value COLLATE "C") INTO rvc_index_ids
            FROM (SELECT DISTINCT value COLLATE "C" AS value
                FROM pg_catalog.unnest(rvc_read_ids || rvc_write_ids) AS value) AS source;
        rvc_before_heads := rv_transition->'indexBeforeHeads';
        rvc_after_heads := rv_transition->'indexAfterHeads';
        IF pg_catalog.jsonb_typeof(rvc_before_heads) IS DISTINCT FROM 'array'
            OR pg_catalog.jsonb_typeof(rvc_after_heads) IS DISTINCT FROM 'array'
            OR pg_catalog.jsonb_typeof(rvc_inputs->'writeFrontiers') IS DISTINCT FROM 'array'
        THEN RAISE EXCEPTION 'revocation counted head or frontier inventory is invalid'; END IF;
        IF pg_catalog.jsonb_array_length(rvc_before_heads) <> pg_catalog.cardinality(rvc_index_ids)
            OR pg_catalog.jsonb_array_length(rvc_after_heads) <> pg_catalog.cardinality(rvc_index_ids)
            OR pg_catalog.jsonb_array_length(rvc_inputs->'writeFrontiers') <> pg_catalog.cardinality(rvc_write_ids)
        THEN RAISE EXCEPTION 'revocation counted head or frontier inventory differs from exact union'; END IF;
        rvc_position := 0;
        FOREACH rvc_index IN ARRAY rvc_write_ids LOOP
            rvc_frontier := rvc_inputs->'writeFrontiers'->rvc_position;
            IF NOT {_closed('rvc_frontier', ('indexId', 'frontier'))}
                OR rvc_frontier->>'indexId' IS DISTINCT FROM rvc_index
                OR pg_catalog.jsonb_typeof(rvc_frontier->'frontier') IS DISTINCT FROM 'array'
            THEN RAISE EXCEPTION 'revocation counted write frontier inventory is not exact sorted source'; END IF;
            IF pg_catalog.jsonb_array_length(rvc_frontier->'frontier') > {bundle._MAX_WRITE_FRONTIER}
            THEN RAISE EXCEPTION 'revocation counted write frontier exceeds source'; END IF;
            rvc_position := rvc_position + 1;
        END LOOP;
        rvc_descriptors := '{{}}'::jsonb; rvc_position := 0;
        FOREACH rvc_index IN ARRAY rvc_index_ids LOOP
            SELECT source.table_name, source.projection_digest INTO STRICT rvc_table, rvc_projection
                FROM (VALUES {profile_values}) AS source(index_id, table_name, projection_digest)
                WHERE source.index_id COLLATE "C" = rvc_index COLLATE "C";
            rvc_empty := {namespace}.catchplate_policy_authority_counted_empty(rvc_index, '');
            rvc_descriptors := rvc_descriptors || pg_catalog.jsonb_build_object(rvc_index,
                pg_catalog.jsonb_build_object('table', rvc_table, 'projection', rvc_projection, 'empty', rvc_empty));
            rvc_before := rvc_before_heads->rvc_position; rvc_after := rvc_after_heads->rvc_position;
            FOREACH rvc_side IN ARRAY ARRAY['before', 'after'] LOOP
                rvc_head := CASE WHEN rvc_side = 'before' THEN rvc_before ELSE rvc_after END;
                IF NOT {_closed('rvc_head', bundle.HEAD_FIELDS)}
                    OR rvc_head->>'indexId' IS DISTINCT FROM rvc_index
                    OR pg_catalog.jsonb_typeof(rvc_head->'rootDigest') IS DISTINCT FROM 'string'
                    OR (rvc_head->>'rootDigest') COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
                THEN RAISE EXCEPTION 'revocation counted compact head is not exact sorted source'; END IF;
                {_counters('rvc_head', ('indexRevision', 'leafCount'))}
                IF (rvc_head->>'indexRevision' = '0' AND rvc_head->>'leafCount' <> '0')
                    OR ((rvc_head->>'leafCount' = '0') IS DISTINCT FROM (rvc_head->>'rootDigest' = rvc_empty))
                THEN RAISE EXCEPTION 'revocation counted compact empty or genesis convention changed'; END IF;
                rvc_matches := 0;
                FOR rvc_primary_head IN SELECT value FROM pg_catalog.jsonb_array_elements(
                    CASE WHEN rvc_side = 'before'
                        THEN (rv_primary->'businessBeforeRoots') || (rv_primary->'authorizationBeforeRoots')
                        ELSE (rv_primary->'businessAfterRoots') || (rv_primary->'authorizationAfterRoots') END)
                    WHERE (value->>'table') COLLATE "C" = rvc_table COLLATE "C"
                LOOP
                    rvc_matches := rvc_matches + 1;
                    IF NOT {_closed('rvc_primary_head', ('table', 'rootRevision', 'rootDigest', 'leafCount'))}
                    THEN RAISE EXCEPTION 'revocation counted primary population shape changed'; END IF;
                    {_counters('rvc_primary_head', ('leafCount',))}
                    IF (rvc_head->>'leafCount')::bigint > (rvc_primary_head->>'leafCount')::bigint
                    THEN RAISE EXCEPTION 'revocation counted population exceeds primary descriptor'; END IF;
                END LOOP;
                IF rvc_matches <> 1 THEN RAISE EXCEPTION 'revocation counted primary population is not unique'; END IF;
            END LOOP;
            rvc_revision_delta := 0; rvc_count_delta := 0;
            FOR rvc_mutation IN SELECT value FROM pg_catalog.jsonb_array_elements(rvc_mutations)
                WHERE (value->>'table') COLLATE "C" = rvc_table COLLATE "C"
            LOOP
                rvc_old_count := 0; rvc_new_count := 0;
                IF rvc_mutation->'expectedRow' <> 'null'::jsonb THEN
                    SELECT pg_catalog.count(*) INTO rvc_old_count FROM (
                        SELECT 1 FROM {namespace}.catchplate_policy_authority_counted_project(
                            rvc_index, rvc_mutation->'expectedRow') LIMIT 2) AS members;
                END IF;
                IF rvc_mutation->'row' <> 'null'::jsonb THEN
                    SELECT pg_catalog.count(*) INTO rvc_new_count FROM (
                        SELECT 1 FROM {namespace}.catchplate_policy_authority_counted_project(
                            rvc_index, rvc_mutation->'row') LIMIT 2) AS members;
                END IF;
                IF rvc_old_count > 1 OR rvc_new_count > 1
                THEN RAISE EXCEPTION 'revocation counted projection cardinality changed'; END IF;
                rvc_revision_delta := rvc_revision_delta + CASE WHEN rvc_old_count + rvc_new_count > 0 THEN 1 ELSE 0 END;
                rvc_count_delta := rvc_count_delta + rvc_new_count - rvc_old_count;
            END LOOP;
            IF (rvc_before->>'indexRevision')::numeric + rvc_revision_delta > 9223372036854775807
                OR (rvc_before->>'leafCount')::numeric + rvc_count_delta NOT BETWEEN 0 AND 9223372036854775807
                OR (rvc_after->>'indexRevision')::numeric IS DISTINCT FROM
                    (rvc_before->>'indexRevision')::numeric + rvc_revision_delta
                OR (rvc_after->>'leafCount')::numeric IS DISTINCT FROM
                    (rvc_before->>'leafCount')::numeric + rvc_count_delta
                OR (rvc_revision_delta = 0 AND rvc_after IS DISTINCT FROM rvc_before)
            THEN RAISE EXCEPTION 'revocation counted projected head delta changed'; END IF;
            rvc_position := rvc_position + 1;
        END LOOP;
        rvc_phase := 1;
    """)


def _read_heads(namespace, *, before):
    expected = "rvc_before_heads" if before else "rvc_after_heads"
    actual = "rvc_actual_before_heads" if before else "rvc_actual_after_heads"
    label = "before" if before else "after"
    return f"""
        {actual} := '[]'::jsonb; rvc_position := 0;
        FOREACH rvc_index IN ARRAY rvc_index_ids LOOP
            rvc_matches := 0;
            FOR rvc_candidate IN
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
                WHERE head.index_id COLLATE "C" = rvc_index COLLATE "C"
                LIMIT 2 {'FOR UPDATE' if before else ''}
            LOOP
                rvc_matches := rvc_matches + 1;
                IF rvc_matches > 1 THEN RAISE EXCEPTION 'revocation counted {label} head is not unique'; END IF;
                rvc_source_head := rvc_candidate;
            END LOOP;
            IF rvc_matches <> 1 THEN RAISE EXCEPTION 'revocation counted {label} head is absent'; END IF;
            IF rvc_source_head.index_id COLLATE "C" IS DISTINCT FROM rvc_index COLLATE "C"
                OR rvc_source_head.table_name COLLATE "C" IS DISTINCT FROM (rvc_descriptors->rvc_index->>'table') COLLATE "C"
                OR rvc_source_head.counted_profile COLLATE "C" IS DISTINCT FROM {_literal(counted.PROFILE)} COLLATE "C"
                OR rvc_source_head.projection_digest COLLATE "C" IS DISTINCT FROM (rvc_descriptors->rvc_index->>'projection') COLLATE "C"
                OR rvc_source_head.projection_manifest_digest COLLATE "C" IS DISTINCT FROM {_literal(projection.projection_manifest_digest())} COLLATE "C"
                OR rvc_source_head.index_revision IS NULL OR rvc_source_head.index_revision < 0
                OR rvc_source_head.leaf_count IS NULL OR rvc_source_head.leaf_count < 0
                OR rvc_source_head.root_digest IS NULL
                OR rvc_source_head.root_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
                OR (rvc_source_head.index_revision = 0 AND rvc_source_head.leaf_count <> 0)
                OR ((rvc_source_head.leaf_count = 0) IS DISTINCT FROM
                    (rvc_source_head.root_digest COLLATE "C" = (rvc_descriptors->rvc_index->>'empty') COLLATE "C"))
            THEN RAISE EXCEPTION 'revocation counted {label} source head contract changed'; END IF;
            rvc_head := pg_catalog.jsonb_build_object('indexId', rvc_source_head.index_id,
                'indexRevision', rvc_source_head.index_revision, 'rootDigest', rvc_source_head.root_digest,
                'leafCount', rvc_source_head.leaf_count);
            IF rvc_head IS DISTINCT FROM {expected}->rvc_position
            THEN RAISE EXCEPTION 'revocation counted {label} live head changed'; END IF;
            {actual} := {actual} || pg_catalog.jsonb_build_array(rvc_head);
            rvc_position := rvc_position + 1;
        END LOOP;
        IF {actual} IS DISTINCT FROM {expected}
        THEN RAISE EXCEPTION 'revocation counted {label} live inventory changed'; END IF;
    """


def lock_and_assert_revocation_counted_before_sql(namespace: str) -> str:
    """Lock/check every source head after the caller's sorted primary locks.

    LIMIT 2 is an explicit fail-closed bound, not missing-head genesis. All
    profiles are locked before mutations, including currently nonmember ones.
    The actual same-transaction locks remain held through the after check.
    """
    _schema_name(namespace)
    return textwrap.dedent(f"""
        IF rvc_phase IS DISTINCT FROM 1
        THEN RAISE EXCEPTION 'revocation counted before phase is invalid'; END IF;
        rvc_phase := -1;
        {_read_heads(namespace, before=True)}
        rvc_phase := 2;
    """)


def assert_revocation_counted_after_sql(namespace: str) -> str:
    """Check the captured planned vector after real triggers, before publication.

    No live observation is permitted without the preceding before-lock phase.
    This fragment does not perform maintenance, consume authority, release locks
    or commit. A later failure belongs to the caller's enclosing transaction.
    """
    _schema_name(namespace)
    return textwrap.dedent(f"""
        IF rvc_phase IS DISTINCT FROM 2
        THEN RAISE EXCEPTION 'revocation counted after phase is invalid'; END IF;
        rvc_phase := -1;
        {_read_heads(namespace, before=False)}
        rvc_phase := 3;
    """)
