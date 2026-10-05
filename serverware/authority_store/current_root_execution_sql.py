"""Same-transaction successor mutation/marker SQL fragments.

This module alone grants nothing. The source-installed successor_execution_sql
bridge loads immutable custody populated by the actual original-byte issuer;
its executor accepts only pending/packet identities. The fixed Python owner
admits actual role/TLS/transaction and independently pinned complete catalog
before and after that call, with a separate durable attempt before connecting.
Neither these variables, a Python candidate carrier nor a digest is an authority
token. A generic JSON-accepting execution wrapper would bypass that boundary.

After that missing admission, the owning function assigns these fixed locals:
crx_operation/request_digest/operation_id (text), crx_selected_rows/crx_mutations
(jsonb arrays of actual replay-derived selected6/mutation7 records),
crx_work_units (actual total replay units, including required capacity effects),
crx_result_json (canonical genuine kernel result), crx_before_vector_json and
crx_after_vector_json (canonical complete vectors), crx_marker (exact18 storage
projection) and crx_deadline_epoch_ns (unchanged independently admitted expiry).
The declarations below include these inputs; all other locals are scratch.
The maintenance begin/finish fragments use the same fixed scalar/vector/marker
locals, but never consume aggregate selected rows, mutations or work units.

The enclosing owner must also admit exact installed schema/ACL/function and
ALL business trigger definitions and retain bounded inherited statement/lock/idle
timeouts. Source integration is not deployed or runtime verified. This body
does not set any writer-token/operation GUC or fake a legacy v3 reserved/planned
row. The old controlled-writer trigger, if attached, requires its genuine token
and transaction-bound reserved capability; current source attaches it to no
tables. The six legacy executor wrappers remain closed and cannot call here.

Actual full root locks, selected-row locks, CAS DML, primary/count trigger effects,
after-vector equality and the immutable marker belong to ONE outer transaction.
Any error must abort that transaction; no exception recovery/retry/commit occurs
here. The result digest is recomputed from the genuine replay result, not from
an invented SQL result or caller-selected success. A later postcommit receipt
may bind the marker, never conversely. SQL parser/driver allocation and trigger
work are not Python H/B/N accounting, and bounded waits are not deadlock freedom.
Canonicalization uses the actual bounded CPython-compatible ASCII wire helper,
not jsonb::text or the distinct UTF-8 tree serializer; original result bytes
must compare exactly before their digest is computed.
"""
from __future__ import annotations
from serverware import authority_native_activation_hold

import json

from serverware import authority_contract as authority
from serverware import authority_current_root_vector as vector
from serverware import authority_primary_contract as primary
from serverware.authority_store import audit_capacity_sql, mutation_sql
from serverware.authority_store.revocation_retained_sql import _closed, _literal
from serverware.authority_store.wire_json_sql import WIRE_JSON_MAX_DEPTH, WIRE_JSON_MAX_NODES


OPERATIONS = authority.CURRENT_ROOT_COMMIT_MARKER_CONTRACT["operations"]
_SELECTED_FIELDS = ("table", "key", "keyDigest", "present", "row", "contractSelector")


def _json(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _source():
    """Static renderer inputs from the actual complete source inventories."""
    primary._require_coverage()
    if (tuple(sorted(operation for operation, spec in authority.OPERATIONS.items()
            if spec["planningMode"] == "typed-successor-planning")) != OPERATIONS
            or tuple(sorted(primary.PRIMARY_KEY_COLUMNS)) != vector.PRIMARY_TABLES
            or tuple(sorted(vector.projection.INDEX_IDS)) != vector.INDEX_IDS):
        raise ValueError("current-root SQL source inventory changed")
    query = primary.source_query_manifest()
    profiles = {(item["indexContract"], item["proofKind"]) for item in query}
    if len(profiles) != 1:
        raise ValueError("current-root SQL primary profiles differ")
    root_profile, proof_profile = next(iter(profiles))
    inventory = {"schema": vector.PRIMARY_INVENTORY_SCHEMA, "schemaVersion": authority.SCHEMA_VERSION,
        "treeDepth": authority.TREE_DEPTH, "treeRadix": authority.TREE_RADIX,
        "rootProfile": root_profile, "proofProfile": proof_profile,
        "tables": [{"table": table, "keyColumns": list(primary.PRIMARY_KEY_COLUMNS[table])}
            for table in vector.PRIMARY_TABLES]}
    header = {"schema": vector.SCHEMA, "schemaVersion": authority.SCHEMA_VERSION,
        "sourceRevision": authority.SOURCE_REVISION, "operationManifestDigest": authority.OPERATION_MANIFEST_DIGEST,
        "queryManifestDigest": primary.source_query_manifest_digest(),
        "authorizationManifestDigest": primary.source_authorization_manifest_digest(),
        "primaryInventoryDigest": primary._manifest_digest(vector.PRIMARY_INVENTORY_SCHEMA, inventory),
        "projectionManifestDigest": vector.projection.projection_manifest_digest()}
    heads = {identity: {"table": vector.projection.profile_for(identity).table,
        "projectionDigest": vector.projection.profile_for(identity).projection_digest}
        for identity in vector.INDEX_IDS}
    operations = {}
    for operation in OPERATIONS:
        spec = authority.operation_spec(operation)
        tables = sorted(set(spec["businessReads"]) | set(spec["businessWrites"]) | set(spec["authorizationReads"]))
        if authority.CURRENT_ROOT_COMMIT_MARKER_TABLE in tables:
            raise ValueError("current-root marker entered business roots")
        operations[operation] = {
            "keys": {table: list(primary.PRIMARY_KEY_COLUMNS[table]) for table in tables},
            "writes": list(spec["businessWrites"]),
            "templates": {item["templateId"]: {"table": item["table"], "mutation": item["mutation"],
                "predicate": item["predicate"], "cardinality": item["cardinality"]}
                for item in spec["mutationTemplates"]},
            "maximumQueryRows": spec["maximumQueryRows"], "maximumMutations": spec["maximumMutations"],
            "maximumWorkUnits": spec["maximumWorkUnits"],
        }
    return header, heads, operations


def _wire(namespace, expression, target, maximum, nodes=WIRE_JSON_MAX_NODES, depth=WIRE_JSON_MAX_DEPTH):
    # Every expression/target is a fixed source local, never caller SQL.
    return f"""
        SELECT * INTO STRICT crx_measured FROM {namespace}.serverware_policy_authority_wire_walk(
            {expression}, {depth}, {nodes}, {maximum}, FALSE);
        SELECT * INTO STRICT crx_rendered FROM {namespace}.serverware_policy_authority_wire_walk(
            {expression}, {depth}, crx_measured.visited_nodes, crx_measured.emitted_bytes, TRUE);
        IF crx_rendered.visited_nodes IS DISTINCT FROM crx_measured.visited_nodes
            OR crx_rendered.emitted_bytes IS DISTINCT FROM crx_measured.emitted_bytes
            OR pg_catalog.octet_length(crx_rendered.rendered) IS DISTINCT FROM crx_measured.emitted_bytes
        THEN RAISE EXCEPTION 'successor SQL canonical measurement changed'; END IF;
        {target} := crx_rendered.rendered;
    """


def _live_sql():
    return """
        IF crx_deadline_epoch_ns IS NULL OR crx_deadline_epoch_ns <= 0
            OR pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000000)
                >= crx_deadline_epoch_ns
        THEN RAISE EXCEPTION 'successor original transaction deadline expired'; END IF;
    """


def current_root_execution_declarations_sql() -> str:
    """Fixed input/scratch locals for one genuinely admitted protected owner call."""
    return """
        crx_operation text; crx_request_digest text; crx_operation_id text;
        crx_selected_rows jsonb; crx_mutations jsonb; crx_work_units bigint;
        crx_result_json text; crx_before_vector_json text; crx_after_vector_json text;
        crx_marker jsonb; crx_deadline_epoch_ns bigint;
        crx_source jsonb; crx_header jsonb; crx_heads jsonb;
        crx_before jsonb; crx_after jsonb; crx_actual jsonb;
        crx_primary jsonb; crx_counted jsonb; crx_counts jsonb;
        crx_canonical text; crx_result_digest text; crx_marker_json text;
        crx_actual_json text; crx_primary_empty text; crx_empty text;
        crx_primary_ids text[]; crx_index_ids text[]; crx_count integer;
        crx_root record; crx_measured record; crx_rendered record;
        crx_selected_json text; crx_mutation_json text; crx_inserted jsonb;
        selected_row jsonb; mutation jsonb; key_columns jsonb;
        current_row jsonb; post_row jsonb; key_names text[]; supplied_key_names text[];
        key_predicate text; update_columns text; matched_count bigint;
    """


def _observe_sql(namespace):
    """Read/lock every source descriptor; never default missing/unknown roots."""
    return f"""
        crx_primary := '[]'::jsonb; crx_counted := '[]'::jsonb; crx_counts := '{{}}'::jsonb;
        crx_count := 0;
        FOR crx_root IN SELECT table_name, manifest_digest, tree_depth, tree_radix,
                root_revision, root_digest, leaf_count
            FROM {namespace}.policy_authority_authenticated_table_roots
            ORDER BY table_name COLLATE "C" LIMIT {len(vector.PRIMARY_TABLES) + 1} FOR UPDATE
        LOOP
            crx_count := crx_count + 1;
            IF crx_count > {len(vector.PRIMARY_TABLES)}
                OR crx_root.table_name IS DISTINCT FROM crx_primary_ids[crx_count]
                OR crx_root.manifest_digest IS DISTINCT FROM crx_header->>'queryManifestDigest'
                OR crx_root.tree_depth IS DISTINCT FROM {authority.TREE_DEPTH}
                OR crx_root.tree_radix IS DISTINCT FROM {authority.TREE_RADIX}
                OR crx_root.root_revision IS NULL OR crx_root.root_revision < 0
                OR crx_root.leaf_count IS NULL OR crx_root.leaf_count < 0
                OR crx_root.root_digest IS NULL OR pg_catalog.octet_length(crx_root.root_digest) <> 71
                OR crx_root.root_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
                OR (crx_root.leaf_count = 0) IS DISTINCT FROM (crx_root.root_digest = crx_primary_empty)
                OR (crx_root.root_revision = 0 AND crx_root.leaf_count <> 0)
            THEN RAISE EXCEPTION 'successor complete primary inventory differs'; END IF;
            crx_primary := crx_primary || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
                'table', crx_root.table_name, 'rootRevision', crx_root.root_revision,
                'rootDigest', crx_root.root_digest, 'leafCount', crx_root.leaf_count));
            crx_counts := crx_counts || pg_catalog.jsonb_build_object(crx_root.table_name, crx_root.leaf_count);
        END LOOP;
        IF crx_count <> {len(vector.PRIMARY_TABLES)} THEN RAISE EXCEPTION 'successor primary inventory is incomplete'; END IF;
        crx_count := 0;
        FOR crx_root IN SELECT index_id, table_name, counted_profile, projection_digest,
                projection_manifest_digest, index_revision, root_digest, leaf_count
            FROM {namespace}.policy_authority_counted_index_heads
            ORDER BY index_id COLLATE "C" LIMIT {len(vector.INDEX_IDS) + 1} FOR UPDATE
        LOOP
            crx_count := crx_count + 1;
            IF crx_count > {len(vector.INDEX_IDS)}
                OR crx_root.index_id IS DISTINCT FROM crx_index_ids[crx_count]
                OR crx_root.table_name IS DISTINCT FROM crx_heads->crx_root.index_id->>'table'
                OR crx_root.counted_profile IS DISTINCT FROM {_literal(vector.counted.PROFILE)}
                OR crx_root.projection_digest IS DISTINCT FROM crx_heads->crx_root.index_id->>'projectionDigest'
                OR crx_root.projection_manifest_digest IS DISTINCT FROM crx_header->>'projectionManifestDigest'
                OR crx_root.index_revision IS NULL OR crx_root.index_revision < 0
                OR crx_root.leaf_count IS NULL OR crx_root.leaf_count < 0
                OR crx_root.leaf_count > (crx_counts->>crx_root.table_name)::bigint
                OR crx_root.root_digest IS NULL OR pg_catalog.octet_length(crx_root.root_digest) <> 71
                OR crx_root.root_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
                OR (crx_root.index_revision = 0 AND crx_root.leaf_count <> 0)
            THEN RAISE EXCEPTION 'successor complete counted inventory differs'; END IF;
            crx_empty := {namespace}.serverware_policy_authority_counted_empty(crx_root.index_id, '');
            IF (crx_root.leaf_count = 0) IS DISTINCT FROM (crx_root.root_digest = crx_empty)
            THEN RAISE EXCEPTION 'successor counted empty root differs'; END IF;
            crx_counted := crx_counted || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
                'indexId', crx_root.index_id, 'table', crx_root.table_name,
                'countedProfile', crx_root.counted_profile, 'projectionDigest', crx_root.projection_digest,
                'projectionManifestDigest', crx_root.projection_manifest_digest,
                'indexRevision', crx_root.index_revision, 'rootDigest', crx_root.root_digest,
                'leafCount', crx_root.leaf_count));
        END LOOP;
        IF crx_count <> {len(vector.INDEX_IDS)} THEN RAISE EXCEPTION 'successor counted inventory is incomplete'; END IF;
        crx_actual := crx_header || pg_catalog.jsonb_build_object('primaryRoots', crx_primary, 'countedRoots', crx_counted);
        {_wire(namespace, 'crx_actual', 'crx_actual_json', vector.MAX_BYTES, vector.MAX_NODES, vector.MAX_DEPTH)}
    """


def _setup_sql(namespace, header, heads, operations):
    """Original transaction, source and complete-descriptor setup."""
    return f"""
        {_live_sql()}
        IF pg_catalog.current_setting('server_version_num')::integer / 10000 <> 16
            OR pg_catalog.current_setting('transaction_isolation') IS DISTINCT FROM 'serializable'
            OR pg_catalog.current_setting('transaction_read_only') IS DISTINCT FROM 'off'
            OR pg_catalog.current_setting('transaction_deferrable') IS DISTINCT FROM 'off'
            OR pg_catalog.current_setting('lock_timeout') = '0'
            OR pg_catalog.current_setting('statement_timeout') = '0'
            OR pg_catalog.current_setting('idle_in_transaction_session_timeout') = '0'
        THEN RAISE EXCEPTION 'successor owner transaction or inherited timeout is not admitted'; END IF;
        crx_source := {_literal(_json(operations))}::jsonb->crx_operation;
        crx_header := {_literal(_json(header))}::jsonb;
        crx_heads := {_literal(_json(heads))}::jsonb;
        crx_primary_ids := ARRAY[{', '.join(_literal(name) for name in vector.PRIMARY_TABLES)}]::text[];
        crx_index_ids := ARRAY[{', '.join(_literal(name) for name in vector.INDEX_IDS)}]::text[];
"""


def _operation_inputs_sql(namespace):
    """Shared exact operation/request identity condition; caller closes its IF."""
    return f"""        IF crx_source IS NULL OR crx_request_digest IS NULL OR crx_operation_id IS NULL
            OR crx_request_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
            OR crx_operation_id IS DISTINCT FROM {namespace}.serverware_policy_authority_domain_digest(
                'serverware.policyAuthorityOperation/v2', crx_operation, crx_request_digest)"""


def _aggregate_inputs_sql(namespace):
    """Unchanged aggregate-only array and genuine replay-work guards."""
    return f"""{_operation_inputs_sql(namespace)}
            OR pg_catalog.jsonb_typeof(crx_selected_rows) IS DISTINCT FROM 'array'
            OR pg_catalog.jsonb_typeof(crx_mutations) IS DISTINCT FROM 'array'
            OR crx_work_units IS NULL OR crx_work_units < 0
            OR crx_work_units > (crx_source->>'maximumWorkUnits')::bigint
        THEN RAISE EXCEPTION 'successor same-call operation inputs differ'; END IF;
        IF pg_catalog.jsonb_array_length(crx_selected_rows) > (crx_source->>'maximumQueryRows')::integer
            OR pg_catalog.jsonb_array_length(crx_mutations) > (crx_source->>'maximumMutations')::integer
        THEN RAISE EXCEPTION 'successor selected or mutation inventory exceeds source limits'; END IF;
        {_wire(namespace, 'crx_selected_rows', 'crx_selected_json', authority.MAX_PLAN_SELECTED_BYTES)}
        {_wire(namespace, 'crx_mutations', 'crx_mutation_json', authority.MAX_RESULT_BYTES)}
"""


def _vectors_marker_sql(namespace):
    """Original canonical vector/result and exact marker-scope validation."""
    digest_checks = " OR ".join(
        f"pg_catalog.jsonb_typeof(crx_marker->{_literal(name)}) IS DISTINCT FROM 'string'"
        f" OR crx_marker->>{_literal(name)} COLLATE \"C\" !~ '^sha256:[0-9a-f]{{64}}$'"
        for name in authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS if name.endswith("_digest"))
    return f"""        IF crx_before_vector_json IS NULL OR crx_after_vector_json IS NULL OR crx_result_json IS NULL
            OR pg_catalog.octet_length(crx_before_vector_json) NOT BETWEEN 2 AND {vector.MAX_BYTES}
            OR pg_catalog.octet_length(crx_after_vector_json) NOT BETWEEN 2 AND {vector.MAX_BYTES}
            OR pg_catalog.octet_length(crx_result_json) NOT BETWEEN 2 AND {authority.MAX_RESULT_BYTES}
        THEN RAISE EXCEPTION 'successor exact vector or result bytes exceed their bounds'; END IF;
        crx_before := crx_before_vector_json::jsonb; crx_after := crx_after_vector_json::jsonb;
        {_wire(namespace, 'crx_before', 'crx_canonical', vector.MAX_BYTES, vector.MAX_NODES, vector.MAX_DEPTH)}
        IF crx_canonical IS DISTINCT FROM crx_before_vector_json THEN RAISE EXCEPTION 'successor before vector is not canonical'; END IF;
        {_wire(namespace, 'crx_after', 'crx_canonical', vector.MAX_BYTES, vector.MAX_NODES, vector.MAX_DEPTH)}
        IF crx_canonical IS DISTINCT FROM crx_after_vector_json THEN RAISE EXCEPTION 'successor after vector is not canonical'; END IF;
        {_wire(namespace, 'crx_result_json::jsonb', 'crx_canonical', authority.MAX_RESULT_BYTES)}
        IF crx_canonical IS DISTINCT FROM crx_result_json THEN RAISE EXCEPTION 'successor actual replay result is not canonical'; END IF;
        crx_result_digest := {namespace}.serverware_policy_authority_domain_digest(
            'serverware.policyAuthorityControlledWriterResult/v2', crx_result_json);
        IF NOT {_closed('crx_marker', authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS)}
            OR {digest_checks}
            OR crx_marker->>'source_revision' IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
            OR crx_marker->>'operation' IS DISTINCT FROM crx_operation
            OR crx_marker->>'request_digest' IS DISTINCT FROM crx_request_digest
            OR crx_marker->>'operation_id' IS DISTINCT FROM crx_operation_id
            OR crx_marker->>'result_digest' IS DISTINCT FROM crx_result_digest
            OR crx_marker->>'before_vector_digest' IS DISTINCT FROM {namespace}.serverware_policy_authority_domain_digest(
                {_literal(vector.IDENTITY_DOMAIN)}, crx_before_vector_json)
            OR crx_marker->>'after_vector_digest' IS DISTINCT FROM {namespace}.serverware_policy_authority_domain_digest(
                {_literal(vector.IDENTITY_DOMAIN)}, crx_after_vector_json)
        THEN RAISE EXCEPTION 'successor marker does not bind its actual same-call inputs'; END IF;
        IF pg_catalog.jsonb_typeof(crx_marker->'database_id') IS DISTINCT FROM 'string'
            OR pg_catalog.octet_length(crx_marker->>'database_id') NOT BETWEEN 1 AND 128
            OR crx_marker->>'database_id' COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{{0,127}}$'
            OR pg_catalog.jsonb_typeof(crx_marker->'pending_sequence') IS DISTINCT FROM 'number'
            OR pg_catalog.jsonb_typeof(crx_marker->'predecessor_sequence') IS DISTINCT FROM 'number'
            OR pg_catalog.jsonb_typeof(crx_marker->'fence') IS DISTINCT FROM 'number'
            OR crx_marker->>'pending_sequence' !~ '^[1-9][0-9]{{0,18}}$'
            OR crx_marker->>'predecessor_sequence' !~ '^(0|[1-9][0-9]{{0,18}})$'
            OR crx_marker->>'fence' !~ '^[1-9][0-9]{{0,18}}$'
        THEN RAISE EXCEPTION 'successor marker scalar scope is not exact'; END IF;
        IF (crx_marker->>'pending_sequence')::numeric > 9223372036854775807
            OR (crx_marker->>'predecessor_sequence')::numeric > 9223372036854775806
            OR (crx_marker->>'fence')::numeric > 9223372036854775807
            OR (crx_marker->>'pending_sequence')::numeric
                <> (crx_marker->>'predecessor_sequence')::numeric + 1
        THEN RAISE EXCEPTION 'successor marker sequence or fence is invalid'; END IF;
        {_wire(namespace, 'crx_marker', 'crx_marker_json', 4096, 64, 2)}
"""


def _locked_before_sql(namespace):
    """Original complete before-root locks and unused marker identity."""
    return f"""        -- Prevent root-row phantoms while locking the complete existing source
        -- inventories. These locks and the following row locks survive until
        -- the outer transaction ends; no missing root is initialized here.
        LOCK TABLE {namespace}.policy_authority_authenticated_table_roots,
            {namespace}.policy_authority_counted_index_heads IN SHARE ROW EXCLUSIVE MODE;
        crx_primary_empty := {namespace}.serverware_policy_authority_authenticated_empty(0);
        {_observe_sql(namespace)}
        IF crx_actual_json IS DISTINCT FROM crx_before_vector_json
        THEN RAISE EXCEPTION 'successor actual locked before vector changed'; END IF;
        IF EXISTS (SELECT 1 FROM {namespace}.{authority.CURRENT_ROOT_COMMIT_MARKER_TABLE} AS marker
            WHERE marker.pending_decision_digest = crx_marker->>'pending_decision_digest'
                OR marker.pending_request_digest = crx_marker->>'pending_request_digest'
                OR (marker.enrollment_digest = crx_marker->>'enrollment_digest' AND (
                    marker.fence = (crx_marker->>'fence')::bigint
                    OR marker.operation_id = crx_operation_id
                    OR marker.capability_digest = crx_marker->>'capability_digest')))
        THEN RAISE EXCEPTION 'successor marker identity is already used'; END IF;
"""


def _aggregate_effects_sql(namespace):
    """Unchanged selected-row, capacity and ordered aggregate CAS body."""
    return f"""        IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(crx_selected_rows) AS item(value)
                GROUP BY item.value->>'table', item.value->'key' HAVING count(*) <> 1)
            OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(crx_mutations) AS item(value)
                GROUP BY item.value->>'table', item.value->'key' HAVING count(*) <> 1)
        THEN RAISE EXCEPTION 'successor selected or mutation key is duplicated'; END IF;
        FOR selected_row IN SELECT item.value FROM pg_catalog.jsonb_array_elements(crx_selected_rows) AS item(value)
            ORDER BY item.value->>'table' COLLATE "C", item.value->>'keyDigest' COLLATE "C"
        LOOP
            IF NOT {_closed('selected_row', _SELECTED_FIELDS)}
                OR (crx_source->'keys' ? (selected_row->>'table')) IS DISTINCT FROM TRUE
                OR pg_catalog.jsonb_typeof(selected_row->'key') IS DISTINCT FROM 'object'
                OR pg_catalog.jsonb_typeof(selected_row->'present') IS DISTINCT FROM 'boolean'
                OR pg_catalog.jsonb_typeof(selected_row->'contractSelector') NOT IN ('null', 'string')
                OR selected_row->>'keyDigest' IS DISTINCT FROM {namespace}.serverware_policy_authority_domain_digest(
                    'serverware.policyAuthorityBusinessKey/v1', selected_row->>'table',
                    {namespace}.serverware_policy_authority_wire_json(selected_row->'key'))
            THEN RAISE EXCEPTION 'successor selected row is outside its source contract'; END IF;
            key_columns := crx_source->'keys'->(selected_row->>'table');
            {mutation_sql.locked_primary_key_row_sql(namespace, 'selected_row')}
            IF NOT {mutation_sql.selected_row_matches_sql('selected_row')}
            THEN RAISE EXCEPTION 'successor selected row changed under its lock'; END IF;
        END LOOP;
        {audit_capacity_sql.assert_audit_capacity_sql(namespace, operation_sql='crx_operation',
            selected_rows_sql='crx_selected_rows', mutations_sql='crx_mutations', work_units_sql='crx_work_units')}
        {_live_sql()}
        -- Keep genuine semantic replay order, including capacity effects.
        {authority_native_activation_hold.sql(namespace, operation_sql='crx_operation', mutations_sql='crx_mutations')}
        FOR mutation IN SELECT item.value FROM pg_catalog.jsonb_array_elements(crx_mutations)
            WITH ORDINALITY AS item(value, ordinal) ORDER BY item.ordinal
        LOOP
            IF NOT {mutation_sql.closed_record_sql('mutation')}
                OR (crx_source->'writes' ? (mutation->>'table')) IS DISTINCT FROM TRUE
                OR crx_source->'templates'->(mutation->>'templateId') IS NULL
                OR crx_source->'templates'->(mutation->>'templateId')->>'table' IS DISTINCT FROM mutation->>'table'
                OR crx_source->'templates'->(mutation->>'templateId')->>'mutation' IS DISTINCT FROM mutation->>'operation'
                OR crx_source->'templates'->(mutation->>'templateId')->>'predicate'
                    IS DISTINCT FROM 'exact-primary-key-and-full-row-cas-v1'
                OR crx_source->'templates'->(mutation->>'templateId')->'cardinality' IS DISTINCT FROM '1'::jsonb
                OR NOT EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(crx_selected_rows) AS item(value)
                    WHERE item.value->'table' = mutation->'table' AND item.value->'key' = mutation->'key'
                        AND item.value->'keyDigest' = mutation->'keyDigest'
                        AND item.value->'row' IS NOT DISTINCT FROM mutation->'expectedRow')
            THEN RAISE EXCEPTION 'successor mutation differs from its source template or selected image'; END IF;
            key_columns := crx_source->'keys'->(mutation->>'table');
            {mutation_sql.apply_mutation_sql(namespace)}
        END LOOP;
"""


def _finish_sql(namespace):
    """Original maintained after-root equality and exact unique marker insert."""
    columns = ", ".join(authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS)
    return f"""        {_observe_sql(namespace)}
        IF crx_actual_json IS DISTINCT FROM crx_after_vector_json
        THEN RAISE EXCEPTION 'successor actual maintained after vector differs'; END IF;
        {_live_sql()}
        INSERT INTO {namespace}.{authority.CURRENT_ROOT_COMMIT_MARKER_TABLE} ({columns})
            SELECT {columns} FROM pg_catalog.jsonb_populate_record(
                NULL::{namespace}.{authority.CURRENT_ROOT_COMMIT_MARKER_TABLE}, crx_marker)
            RETURNING pg_catalog.to_jsonb({authority.CURRENT_ROOT_COMMIT_MARKER_TABLE}) INTO crx_inserted;
        GET DIAGNOSTICS matched_count = ROW_COUNT;
        IF matched_count <> 1 OR crx_inserted IS DISTINCT FROM crx_marker
        THEN RAISE EXCEPTION 'successor immutable marker insertion was not exact'; END IF;
        {_live_sql()}
    """


def current_root_execution_apply_body_sql(namespace: str) -> str:
    """Render the unchanged aggregate body from the shared exact fragments.

    All original guards and statement order remain, including actual selected
    rows/mutations/work units. This remains only a protected-owner fragment.
    """
    mutation_sql._schema_name(namespace)
    header, heads, operations = _source()
    return (_setup_sql(namespace, header, heads, operations)
        + _aggregate_inputs_sql(namespace) + _vectors_marker_sql(namespace)
        + _locked_before_sql(namespace) + _aggregate_effects_sql(namespace) + _finish_sql(namespace))


def _maintenance_only_sql():
    return """
        IF crx_operation IS DISTINCT FROM 'webauthn.challenge.maintain'
        THEN RAISE EXCEPTION 'maintenance execution operation is not source fixed'; END IF;
    """


def maintenance_execution_begin_sql(namespace: str) -> str:
    """Lock complete predecessors for the genuine sealed maintenance stream.

    Only fixed crx operation/request/id/result/vectors/marker/deadline locals
    are inputs. No aggregate selected rows, mutations or invented work units
    are supplied. The protected caller owns every intervening source step and
    the single outer transaction; this fragment provides no admission itself.
    """
    from serverware.authority_store import challenge_maintenance_effects_sql as maintenance

    mutation_sql._schema_name(namespace)
    # Reuse the actual row/phase renderer's exact UPDATE/DELETE source check,
    # including all nine maintained profiles; do not clone its validator.
    maintenance._source()
    header, heads, operations = _source()
    selected = {maintenance.OPERATION: operations[maintenance.OPERATION]}
    return (_maintenance_only_sql() + _setup_sql(namespace, header, heads, selected)
        + _operation_inputs_sql(namespace)
        + "\n        THEN RAISE EXCEPTION 'successor same-call operation inputs differ'; END IF;\n"
        + _vectors_marker_sql(namespace) + _locked_before_sql(namespace))


def maintenance_execution_finish_sql(namespace: str) -> str:
    """Close that same transaction after every genuine maintenance stream step.

    The original complete after vector must match before the one unique marker
    INSERT. No SQL authority, retry, commit or prior-marker success is added.
    """
    mutation_sql._schema_name(namespace)
    return _maintenance_only_sql() + _finish_sql(namespace)
