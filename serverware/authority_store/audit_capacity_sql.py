"""Independent, pre-DML SQL admission of the compact global outbox count.

This fragment consumes complete, already authenticated selected rows and a
source-admitted operation. It rederives membership changes; it does not trust a
caller delta, read current database rows, initialize a counter, prove root
currentness, or deliver an audit event. The caller must retain its existing
proof, lock, CAS, operation/signature and after-root checks around this guard.
JSONB has already lost duplicate keys/raw number spelling: the caller's exact
canonical transport admission remains mandatory.
"""
from __future__ import annotations

import json
import re
import textwrap

from serverware import authority_contract
from serverware.audit_outbox_contract import MAX_PENDING
from serverware.authority_primary_contract import PRIMARY_KEY_COLUMNS
from serverware.authority_store.mutation_sql import _schema_name
from serverware.authority_store.wire_json_sql import WIRE_JSON_MAX_DEPTH, WIRE_JSON_MAX_NODES


_AGGREGATE_TABLE = "policy_authority_bounded_aggregate_states"
_OUTBOX_TABLE = "metadata_audit_outbox"
_KIND = "metadata-audit-outbox-global-capacity-v1"
_ROW_FIELDS = (
    "aggregate_id", "aggregate_kind", "partition_digest", "revision",
    "live_count", "active_count", "capacity_limit", "reserved_units_json",
    "committed_units_json", "next_sequence", "minimum_expiry_epoch_ns",
    "expiry_index_root_digest", "work_page_id", "state_json", "state_digest",
    "updated_at_epoch_ns", "source_revision",
)
_SELECTED_FIELDS = ("table", "key", "keyDigest", "present", "row", "contractSelector")
_MUTATION_FIELDS = ("table", "key", "keyDigest", "operation", "expectedRow", "row", "templateId")
_I64_MAX = 9_223_372_036_854_775_807
MAX_COUNTER_BYTES = 4096
AUDIT_CAPACITY_FUNCTION_NAME = "serverware_policy_authority_assert_audit_capacity"


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _expression(value: str, *, array: bool) -> str:
    # Source-owned local/record names only; values belong in bound variables,
    # never interpolated SQL literals or arbitrary expression fragments.
    suffix = r"(?:::pg_catalog\.jsonb)?" if array else ""
    if type(value) is not str or re.fullmatch(
        r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)?" + suffix, value
    ) is None:
        raise ValueError("audit capacity input must be an exact SQL variable")
    return value


def _closed(expression: str, fields: tuple[str, ...]) -> str:
    expected = ", ".join(_literal(field) for field in sorted(fields))
    return f"""(CASE WHEN pg_catalog.jsonb_typeof({expression})
        IS DISTINCT FROM 'object' THEN FALSE ELSE
        (SELECT pg_catalog.array_agg(field ORDER BY field COLLATE "C")
         FROM pg_catalog.jsonb_object_keys({expression}) AS field)
        IS NOT DISTINCT FROM ARRAY[{expected}]::text[] END)"""


def _source_contract() -> str:
    value = {}
    for operation in authority_contract.OPERATIONS:
        spec = authority_contract.operation_spec(operation)
        value[operation] = {
            "participates": _OUTBOX_TABLE in spec["businessWrites"],
            "counterPermission": (
                _AGGREGATE_TABLE in spec["businessWrites"]
                and "aggregate-high-water" in spec["proofPrimitives"]
                and any(item["table"] == _AGGREGATE_TABLE and item["mutation"] == "UPDATE"
                    for item in spec["mutationTemplates"])
            ),
            "maximumQueryRows": spec["maximumQueryRows"],
            "maximumMutations": spec["maximumMutations"],
            "keys": {
                table: sorted(PRIMARY_KEY_COLUMNS[table])
                for table in sorted(set(spec["businessReads"]) | set(spec["businessWrites"])
                    | set(spec["authorizationReads"]))
            },
            "templates": {
                item["templateId"]: {
                    "table": item["table"], "mutation": item["mutation"],
                    "predicate": item["predicate"], "cardinality": item["cardinality"],
                }
                for item in spec["mutationTemplates"]
            },
        }
    return _literal(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def assert_audit_capacity_sql(
    namespace: str, *, operation_sql: str, selected_rows_sql: str, mutations_sql: str,
) -> str:
    """Render a nested block before *any* business DML, never a DB writer.

    The expressions name caller variables (optionally record-qualified); array
    variables may carry an explicit ``::pg_catalog.jsonb`` cast. Every mutation
    is checked against the source operation's templates and its unique exact
    selected before image. Only outbox/global-counter rows affect this arithmetic.
    A terminal replay with no outbox mutations must not change the global row.
    """
    _schema_name(namespace)
    operation = _expression(operation_sql, array=False)
    selected = _expression(selected_rows_sql, array=True)
    mutations = _expression(mutations_sql, array=True)
    return textwrap.dedent(f"""
        <<audit_capacity_guard>>
        DECLARE
            ac_operation text := {operation};
            ac_selected pg_catalog.jsonb := {selected};
            ac_mutations pg_catalog.jsonb := {mutations};
            ac_contract constant pg_catalog.jsonb := {_source_contract()}::pg_catalog.jsonb;
            ac_spec pg_catalog.jsonb;
            ac_partition text := {namespace}.serverware_policy_authority_domain_digest(
                'serverware.metadataAuditOutboxCapacityPartition/v1', 'global');
            ac_id text := '{_KIND}:' || ac_partition;
            ac_empty_expiry text := {namespace}.serverware_policy_authority_domain_digest(
                'serverware.policyAuthorityAggregateExpiryIndex/v1', '[]');
            ac_selection pg_catalog.jsonb;
            ac_mutation pg_catalog.jsonb;
            ac_template pg_catalog.jsonb;
            ac_key pg_catalog.jsonb;
            ac_key_field text;
            ac_before pg_catalog.jsonb;
            ac_after pg_catalog.jsonb;
            ac_row pg_catalog.jsonb;
            ac_field text;
            ac_state pg_catalog.jsonb;
            ac_state_text text;
            ac_counter pg_catalog.jsonb;
            ac_global_selection pg_catalog.jsonb;
            ac_expected pg_catalog.jsonb;
            ac_outbox_count bigint := 0;
            ac_counter_count bigint := 0;
            ac_delta bigint := 0;
            ac_insert_count bigint := 0;
            ac_old_member bigint;
            ac_new_member bigint;
            ac_next_count numeric;
            ac_next_sequence numeric;
            ac_inventory_bytes bigint;
        BEGIN
            IF (ac_contract ? ac_operation) IS NOT TRUE
                OR pg_catalog.jsonb_typeof(ac_selected) IS DISTINCT FROM 'array'
                OR pg_catalog.jsonb_typeof(ac_mutations) IS DISTINCT FROM 'array'
            THEN
                RAISE EXCEPTION 'authority audit capacity inputs are not source-bounded arrays';
            END IF;
            ac_spec := ac_contract->ac_operation;
            IF ac_spec->'participates' = 'true'::pg_catalog.jsonb
                AND ac_spec->'counterPermission' IS DISTINCT FROM 'true'::pg_catalog.jsonb
            THEN
                RAISE EXCEPTION 'authority audit capacity operation lacks the source counter contract';
            END IF;
            IF pg_catalog.jsonb_array_length(ac_selected) >
                    (ac_spec->>'maximumQueryRows')::bigint
                OR pg_catalog.jsonb_array_length(ac_mutations) >
                    (ac_spec->>'maximumMutations')::bigint
            THEN
                RAISE EXCEPTION 'authority audit capacity operation bound is exceeded';
            END IF;
            -- Same outer [selected, mutations] root as the pure validator:
            -- depth starts at zero and object keys count as visited children.
            -- Measure/validate the full graph with the narrower 64 MiB budget;
            -- do not allocate the wire renderer's possible 72 MiB output.
            SELECT measured.emitted_bytes INTO STRICT ac_inventory_bytes
            FROM {namespace}.serverware_policy_authority_wire_walk(
                pg_catalog.jsonb_build_array(ac_selected, ac_mutations),
                {WIRE_JSON_MAX_DEPTH}, {WIRE_JSON_MAX_NODES}, {authority_contract.MAX_RESULT_BYTES}, FALSE
            ) AS measured;
            IF ac_inventory_bytes NOT BETWEEN 1 AND {authority_contract.MAX_RESULT_BYTES} THEN
                RAISE EXCEPTION 'authority audit capacity inventory byte bound is exceeded';
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_catalog.jsonb_array_elements(ac_selected) AS item(value)
                GROUP BY item.value->>'table', item.value->'key' HAVING pg_catalog.count(*) <> 1
            ) OR EXISTS (
                SELECT 1 FROM pg_catalog.jsonb_array_elements(ac_mutations) AS item(value)
                GROUP BY item.value->>'table', item.value->'key' HAVING pg_catalog.count(*) <> 1
            ) THEN
                RAISE EXCEPTION 'authority audit capacity selected or mutation identity is duplicated';
            END IF;
            FOR ac_selection IN
                SELECT value FROM pg_catalog.jsonb_array_elements(ac_selected)
            LOOP
                IF NOT {_closed('ac_selection', _SELECTED_FIELDS)}
                    OR pg_catalog.jsonb_typeof(ac_selection->'table') IS DISTINCT FROM 'string'
                    OR (ac_spec->'keys' ? (ac_selection->>'table')) IS NOT TRUE
                    OR pg_catalog.jsonb_typeof(ac_selection->'key') IS DISTINCT FROM 'object'
                    OR (ac_selection->'key' = '{{}}'::pg_catalog.jsonb) IS NOT FALSE
                    OR (pg_catalog.jsonb_typeof(ac_selection->'contractSelector')
                        IN ('null', 'string')) IS NOT TRUE
                    OR ac_selection->>'keyDigest' IS DISTINCT FROM
                        {namespace}.serverware_policy_authority_domain_digest(
                            'serverware.policyAuthorityBusinessKey/v1', ac_selection->>'table',
                            {namespace}.serverware_policy_authority_wire_json(ac_selection->'key'))
                THEN
                    RAISE EXCEPTION 'authority audit capacity selected record is not exact';
                END IF;
                IF (SELECT pg_catalog.jsonb_agg(field ORDER BY field COLLATE "C")
                    FROM pg_catalog.jsonb_object_keys(ac_selection->'key') AS field)
                    IS DISTINCT FROM ac_spec->'keys'->(ac_selection->>'table')
                    OR EXISTS (
                        SELECT 1 FROM pg_catalog.jsonb_each(ac_selection->'key') AS item
                        WHERE (pg_catalog.jsonb_typeof(item.value) IN ('string', 'number', 'boolean')) IS NOT TRUE
                            OR (pg_catalog.jsonb_typeof(item.value) = 'number'
                                AND (item.value::text ~ '^-?(0|[1-9][0-9]*)$') IS NOT TRUE)
                    )
                THEN
                    RAISE EXCEPTION 'authority audit capacity selected primary key is not source-exact';
                END IF;
                IF NOT (CASE ac_selection->'present'
                    WHEN 'true'::pg_catalog.jsonb THEN
                        pg_catalog.jsonb_typeof(ac_selection->'row') IS NOT DISTINCT FROM 'object'
                    WHEN 'false'::pg_catalog.jsonb THEN
                        ac_selection->'row' IS NOT DISTINCT FROM 'null'::pg_catalog.jsonb
                    ELSE FALSE END)
                THEN
                    RAISE EXCEPTION 'authority audit capacity selected presence is not exact';
                END IF;
                IF ac_selection->'present' = 'true'::pg_catalog.jsonb THEN
                    FOR ac_key_field IN SELECT pg_catalog.jsonb_object_keys(ac_selection->'key') LOOP
                        IF ac_selection->'row'->ac_key_field IS DISTINCT FROM
                            ac_selection->'key'->ac_key_field THEN
                            RAISE EXCEPTION 'authority audit capacity selected row key is crossed';
                        END IF;
                    END LOOP;
                END IF;
                IF ac_selection->>'table' = '{_OUTBOX_TABLE}' AND (
                    NOT {_closed("ac_selection->'key'", ('id',))}
                    OR pg_catalog.jsonb_typeof(ac_selection->'key'->'id') IS DISTINCT FROM 'string'
                    OR pg_catalog.octet_length(ac_selection->'key'->>'id') NOT BETWEEN 1 AND 256
                ) THEN
                    RAISE EXCEPTION 'authority audit capacity outbox selector is not exact';
                END IF;
                IF ac_selection->>'table' = '{_AGGREGATE_TABLE}' AND (
                    ac_selection->'key'->>'aggregate_id' = ac_id
                    OR ac_selection->'row'->>'aggregate_id' = ac_id
                    OR ac_selection->'row'->>'aggregate_kind' = '{_KIND}'
                    OR ac_selection->'row'->>'partition_digest' = ac_partition
                ) THEN
                    IF ac_selection->'key' IS DISTINCT FROM
                            pg_catalog.jsonb_build_object('aggregate_id', ac_id)
                        OR ac_selection->'present' IS DISTINCT FROM 'true'::pg_catalog.jsonb
                        OR ac_global_selection IS NOT NULL
                    THEN
                        RAISE EXCEPTION 'authority audit capacity global selection is crossed or absent';
                    END IF;
                    ac_global_selection := ac_selection;
                END IF;
            END LOOP;
            IF ac_spec->'participates' = 'true'::pg_catalog.jsonb
                AND ac_global_selection IS NULL
            THEN
                RAISE EXCEPTION 'authority audit capacity participating operation lacks global selection';
            END IF;
            IF ac_spec->'participates' <> 'true'::pg_catalog.jsonb
                AND ac_global_selection IS NOT NULL
            THEN
                RAISE EXCEPTION 'authority audit capacity nonparticipant selected the reserved global row';
            END IF;

            FOR ac_mutation IN
                SELECT value FROM pg_catalog.jsonb_array_elements(ac_mutations)
            LOOP
                IF NOT {_closed('ac_mutation', _MUTATION_FIELDS)}
                    OR pg_catalog.jsonb_typeof(ac_mutation->'table') IS DISTINCT FROM 'string'
                    OR pg_catalog.jsonb_typeof(ac_mutation->'key') IS DISTINCT FROM 'object'
                    OR pg_catalog.jsonb_typeof(ac_mutation->'templateId') IS DISTINCT FROM 'string'
                    OR pg_catalog.jsonb_typeof(ac_mutation->'operation') IS DISTINCT FROM 'string'
                THEN
                    RAISE EXCEPTION 'authority audit capacity mutation record is not exact';
                END IF;
                ac_template := ac_spec->'templates'->(ac_mutation->>'templateId');
                IF ac_template IS NULL
                    OR ac_template->'table' IS DISTINCT FROM ac_mutation->'table'
                    OR ac_template->'mutation' IS DISTINCT FROM ac_mutation->'operation'
                    OR ac_template->>'predicate' IS DISTINCT FROM 'exact-primary-key-and-full-row-cas-v1'
                    OR ac_template->'cardinality' IS DISTINCT FROM '1'::pg_catalog.jsonb
                    OR ac_mutation->>'keyDigest' IS DISTINCT FROM
                        {namespace}.serverware_policy_authority_domain_digest(
                            'serverware.policyAuthorityBusinessKey/v1', ac_mutation->>'table',
                            {namespace}.serverware_policy_authority_wire_json(ac_mutation->'key'))
                THEN
                    RAISE EXCEPTION 'authority audit capacity mutation is outside the source template';
                END IF;
                SELECT item.value INTO ac_selection
                FROM pg_catalog.jsonb_array_elements(ac_selected) AS item(value)
                WHERE item.value->'table' = ac_mutation->'table'
                    AND item.value->'key' = ac_mutation->'key';
                IF ac_selection IS NULL
                    OR ac_mutation->'expectedRow' IS DISTINCT FROM ac_selection->'row'
                    OR (ac_mutation->>'operation' = 'INSERT'
                        AND ac_selection->'present' IS DISTINCT FROM 'false'::pg_catalog.jsonb)
                    OR (ac_mutation->>'operation' IN ('UPDATE', 'DELETE')
                        AND ac_selection->'present' IS DISTINCT FROM 'true'::pg_catalog.jsonb)
                    OR (ac_mutation->>'operation' = 'DELETE'
                        AND ac_mutation->'row' IS DISTINCT FROM 'null'::pg_catalog.jsonb)
                    OR (ac_mutation->>'operation' <> 'DELETE'
                        AND pg_catalog.jsonb_typeof(ac_mutation->'row') IS DISTINCT FROM 'object')
                THEN
                    RAISE EXCEPTION 'authority audit capacity mutation before or after image is not exact';
                END IF;
                ac_key := ac_mutation->'key';
                ac_before := ac_mutation->'expectedRow';
                ac_after := ac_mutation->'row';
                IF ac_mutation->>'operation' <> 'DELETE' THEN
                    FOR ac_key_field IN SELECT pg_catalog.jsonb_object_keys(ac_key) LOOP
                        IF ac_after->ac_key_field IS DISTINCT FROM ac_key->ac_key_field THEN
                            RAISE EXCEPTION 'authority audit capacity mutation moves its key';
                        END IF;
                    END LOOP;
                END IF;
                IF ac_mutation->>'table' = '{_OUTBOX_TABLE}' THEN
                    ac_outbox_count := ac_outbox_count + 1;
                    IF (ac_before <> 'null'::pg_catalog.jsonb AND
                        (ac_before->>'status' IN ('pending', 'claimed', 'audited')) IS NOT TRUE)
                        OR (ac_after <> 'null'::pg_catalog.jsonb AND
                        (ac_after->>'status' IN ('pending', 'claimed', 'audited')) IS NOT TRUE)
                        OR (ac_mutation->>'operation' = 'INSERT'
                            AND ac_after->'status' IS DISTINCT FROM '"pending"'::pg_catalog.jsonb)
                        OR (ac_before->>'status' = 'audited'
                            AND ac_after <> 'null'::pg_catalog.jsonb
                            AND ac_after->'status' IS DISTINCT FROM '"audited"'::pg_catalog.jsonb)
                    THEN
                        RAISE EXCEPTION 'authority audit capacity outbox status transition is invalid';
                    END IF;
                    ac_old_member := CASE WHEN ac_before->>'status' IN ('pending', 'claimed') THEN 1 ELSE 0 END;
                    ac_new_member := CASE WHEN ac_after->>'status' IN ('pending', 'claimed') THEN 1 ELSE 0 END;
                    ac_delta := ac_delta + ac_new_member - ac_old_member;
                    IF ac_mutation->>'operation' = 'INSERT' THEN
                        ac_insert_count := ac_insert_count + 1;
                    END IF;
                ELSIF ac_mutation->>'table' = '{_AGGREGATE_TABLE}' AND (
                    ac_key->>'aggregate_id' = ac_id
                    OR ac_before->>'aggregate_id' = ac_id OR ac_after->>'aggregate_id' = ac_id
                    OR ac_before->>'aggregate_kind' = '{_KIND}' OR ac_after->>'aggregate_kind' = '{_KIND}'
                    OR ac_before->>'partition_digest' = ac_partition OR ac_after->>'partition_digest' = ac_partition
                ) THEN
                    ac_counter_count := ac_counter_count + 1;
                    ac_counter := ac_mutation;
                    IF ac_key IS DISTINCT FROM pg_catalog.jsonb_build_object('aggregate_id', ac_id)
                        OR ac_mutation->>'operation' IS DISTINCT FROM 'UPDATE'
                    THEN
                        RAISE EXCEPTION 'authority audit capacity global mutation is crossed or bootstrapped';
                    END IF;
                END IF;
            END LOOP;
            IF (ac_outbox_count = 0 AND ac_counter_count <> 0)
                OR (ac_outbox_count > 0 AND ac_counter_count <> 1)
                OR (ac_counter_count <> 0 AND ac_spec->'participates' <> 'true'::pg_catalog.jsonb)
            THEN
                RAISE EXCEPTION 'authority audit capacity global mutation closure is incomplete';
            END IF;
            IF ac_spec->'participates' = 'true'::pg_catalog.jsonb THEN
                ac_before := ac_global_selection->'row';
                ac_after := ac_counter->'row';
                FOR ac_row IN SELECT value FROM pg_catalog.jsonb_array_elements(
                    CASE WHEN ac_counter_count = 1
                        THEN pg_catalog.jsonb_build_array(ac_before, ac_after)
                        ELSE pg_catalog.jsonb_build_array(ac_before) END)
                LOOP
                    IF NOT {_closed('ac_row', _ROW_FIELDS)} THEN
                        RAISE EXCEPTION 'authority audit capacity global row is not closed';
                    END IF;
                    IF pg_catalog.octet_length(
                        {namespace}.serverware_policy_authority_wire_json(ac_row)) > {MAX_COUNTER_BYTES}
                    THEN
                        RAISE EXCEPTION 'authority audit capacity global row exceeds its compact byte bound';
                    END IF;
                    FOREACH ac_field IN ARRAY ARRAY['revision', 'live_count', 'active_count',
                        'capacity_limit', 'next_sequence', 'updated_at_epoch_ns']::text[]
                    LOOP
                        IF pg_catalog.jsonb_typeof(ac_row->ac_field) IS DISTINCT FROM 'number'
                            OR (ac_row->>ac_field ~ '^(0|[1-9][0-9]{{0,18}})$') IS NOT TRUE
                        THEN
                            RAISE EXCEPTION 'authority audit capacity counter is not an exact integer';
                        END IF;
                        IF (ac_row->>ac_field)::numeric > {_I64_MAX} THEN
                            RAISE EXCEPTION 'authority audit capacity counter exceeds signed bigint';
                        END IF;
                    END LOOP;
                    IF ac_row->'aggregate_id' IS DISTINCT FROM pg_catalog.to_jsonb(ac_id)
                        OR ac_row->'aggregate_kind' IS DISTINCT FROM pg_catalog.to_jsonb('{_KIND}'::text)
                        OR ac_row->'partition_digest' IS DISTINCT FROM pg_catalog.to_jsonb(ac_partition)
                        OR (ac_row->>'revision')::bigint < 1
                        OR ac_row->'capacity_limit' IS DISTINCT FROM '{MAX_PENDING}'::pg_catalog.jsonb
                        OR ac_row->'live_count' IS DISTINCT FROM ac_row->'active_count'
                        OR (ac_row->>'live_count')::bigint > {MAX_PENDING}
                        OR ac_row->'reserved_units_json' IS DISTINCT FROM pg_catalog.to_jsonb('{{}}'::text)
                        OR ac_row->'committed_units_json' IS DISTINCT FROM pg_catalog.to_jsonb('{{}}'::text)
                        OR ac_row->'minimum_expiry_epoch_ns' IS DISTINCT FROM 'null'::pg_catalog.jsonb
                        OR ac_row->'work_page_id' IS DISTINCT FROM 'null'::pg_catalog.jsonb
                        OR ac_row->'expiry_index_root_digest' IS DISTINCT FROM pg_catalog.to_jsonb(ac_empty_expiry)
                        OR ac_row->'source_revision' IS DISTINCT FROM
                            pg_catalog.to_jsonb({_literal(authority_contract.SOURCE_REVISION)}::text)
                    THEN
                        RAISE EXCEPTION 'authority audit capacity global profile is invalid';
                    END IF;
                    ac_state := pg_catalog.jsonb_build_object(
                        'schema', 'serverware.policyAuthorityAggregateState/v1',
                        'aggregateId', ac_row->'aggregate_id', 'aggregateKind', ac_row->'aggregate_kind',
                        'partitionDigest', ac_row->'partition_digest', 'revision', ac_row->'revision',
                        'liveCount', ac_row->'live_count', 'activeCount', ac_row->'active_count',
                        'capacityLimit', ac_row->'capacity_limit', 'reservedUnits', '{{}}'::pg_catalog.jsonb,
                        'committedUnits', '{{}}'::pg_catalog.jsonb, 'nextSequence', ac_row->'next_sequence',
                        'minimumExpiryEpochNs', ac_row->'minimum_expiry_epoch_ns',
                        'expiryIndexRootDigest', ac_row->'expiry_index_root_digest', 'workPageId', ac_row->'work_page_id');
                    ac_state_text := {namespace}.serverware_policy_authority_wire_json(ac_state);
                    IF ac_row->'state_json' IS DISTINCT FROM pg_catalog.to_jsonb(ac_state_text)
                        OR ac_row->'state_digest' IS DISTINCT FROM pg_catalog.to_jsonb(
                            {namespace}.serverware_policy_authority_domain_digest(
                                'serverware.policyAuthorityAggregateState/v1', ac_state_text))
                    THEN
                        RAISE EXCEPTION 'authority audit capacity state framing is invalid';
                    END IF;
                END LOOP;
                IF ac_outbox_count > 0 THEN
                    ac_next_count := (ac_before->>'live_count')::numeric + ac_delta;
                    ac_next_sequence := (ac_before->>'next_sequence')::numeric + ac_insert_count;
                    IF ac_next_count NOT BETWEEN 0 AND {MAX_PENDING}
                        OR ac_next_sequence > {_I64_MAX}
                        OR (ac_before->>'revision')::bigint = {_I64_MAX}
                        OR (ac_after->>'updated_at_epoch_ns')::bigint <
                            (ac_before->>'updated_at_epoch_ns')::bigint
                    THEN
                        RAISE EXCEPTION 'authority audit capacity derived transition is outside its bound';
                    END IF;
                    ac_expected := ac_before || pg_catalog.jsonb_build_object(
                        'revision', (ac_before->>'revision')::bigint + 1,
                        'live_count', ac_next_count::bigint, 'active_count', ac_next_count::bigint,
                        'next_sequence', ac_next_sequence::bigint,
                        'updated_at_epoch_ns', ac_after->'updated_at_epoch_ns',
                        'state_json', ac_after->'state_json', 'state_digest', ac_after->'state_digest');
                    IF ac_after IS DISTINCT FROM ac_expected THEN
                        RAISE EXCEPTION 'authority audit capacity derived after row is not exact';
                    END IF;
                END IF;
            END IF;
        END audit_capacity_guard;
    """)


def audit_capacity_function_sql(namespace: str) -> str:
    """Render the same guard as a closed, invoker-rights function for binds.

    Installation, exact function-definition admission and EXECUTE privileges
    belong to the source-owned schema installer. Reservation invokes it using
    real bound parameters; it must not interpolate parameters into a DO body.
    """
    _schema_name(namespace)
    block = assert_audit_capacity_sql(
        namespace, operation_sql="supplied_operation",
        selected_rows_sql="supplied_selected_rows", mutations_sql="supplied_mutations",
    )
    return textwrap.dedent(f"""
        CREATE OR REPLACE FUNCTION {namespace}.{AUDIT_CAPACITY_FUNCTION_NAME}(
            supplied_operation text,
            supplied_selected_rows pg_catalog.jsonb,
            supplied_mutations pg_catalog.jsonb
        )
        RETURNS void
        LANGUAGE plpgsql
        SECURITY INVOKER
        VOLATILE
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $serverware_audit_capacity$
        BEGIN
        {block}
        END;
        $serverware_audit_capacity$;
    """)
