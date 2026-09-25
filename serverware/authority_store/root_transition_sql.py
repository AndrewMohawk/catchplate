"""Shared SQL admission of a persisted, snapshot-bound primary-root transition.

This is the store half of the measured primary-tree delta contract. It never
derives root authority from the database and does not verify range completeness.
The planner and its independent signature consumer recompute the delta; these
fragments bind the exact persisted plan and compare the transaction's roots.
The component fixture executes these exact fragments, not a parallel guard.
"""
from __future__ import annotations

import json
import textwrap

from serverware import authority_contract, authority_transition_registry
from serverware.authority_radix_proof import empty_digest
from serverware.authority_root_transition import (
    ROOT_FIELDS as _ROOT_FIELDS,
    TRANSITION_FIELDS as _TRANSITION_FIELDS,
    TRANSITION_PROFILE,
    TRANSITION_SCHEMA,
    metric_bounds,
)
from serverware.authority_store.mutation_sql import _schema_name


_PAYLOAD_FIELDS = (
    "schema", "measuredPlan", "typedRequest", "selectedBusinessRows",
    "mutationPlan", "queryMultiproofs", "queryMultiproofsDigest",
    "plannerTrace", "plannerTraceDigest", "authorizationProjection",
    "webauthnEvidence", "expectedResult", "expectedResultDigest",
    "plannerIdentity", "rootTransition",
)
_PLAN_FIELDS = (
    "schema", "plannerTransactionId", "operation", "operationId",
    "requestDigest", "capabilityId", "sourceRevision", "authoritySchemaVersion",
    "operationContractDigest", "operationManifestDigest", "handlerContractDigest",
    "queryManifestDigest", "selectedBusinessRowsDigest", "mutationPlanDigest",
    "workUnits", "authorityRootSetBeforeDigest", "authorizationProjectionDigest",
    "authoritySnapshotDigest", "deadlineMonotonicNs", "deadlineEpochNs", "fence",
    "rootTransitionDigest",
)


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _exact_keys(expression: str, fields: tuple[str, ...] | frozenset[str]) -> str:
    # json (not jsonb) preserves duplicate members: a repeated member is not an
    # exact closed record even if jsonb would silently keep its last value.
    expected = ", ".join(_literal(field) for field in sorted(fields))
    return f"""(CASE WHEN pg_catalog.json_typeof({expression})
        IS DISTINCT FROM 'object' THEN FALSE ELSE
        (SELECT pg_catalog.array_agg(key ORDER BY key COLLATE "C")
         FROM pg_catalog.json_object_keys({expression}) AS key)
        IS NOT DISTINCT FROM ARRAY[{expected}]::text[] END)"""


def root_transition_declarations_sql() -> str:
    return """
        rt_plan_bytes bytea;
        rt_plan_text text;
        rt_payload_json pg_catalog.json;
        rt_payload pg_catalog.jsonb;
        rt_plan_json pg_catalog.json;
        rt_plan pg_catalog.jsonb;
        rt_transition_json pg_catalog.json;
        rt_transition pg_catalog.jsonb;
        rt_transition_digest text;
        rt_snapshot_digest text;
        rt_expected_after_digest text;
        rt_expected_authorization_after_digest text;
        rt_actual_authorization_after_json text;
        rt_field text;
        rt_root_json pg_catalog.json;
        rt_previous_table text;
        rt_table_names pg_catalog.jsonb;
        rt_expected_table_names pg_catalog.jsonb;
    """


def load_root_transition_sql(namespace: str) -> str:
    """Validate stored exact plan and expose its snapshot-bound root vectors.

Requires locked ``planner`` and ``capability`` records plus the declarations
above. It admits only the legacy v3 lifecycle tag, before decoding any plan
bytes or entering the committed-retry branch, without reading current root
heads. The complete plan is ASCII transport, possibly containing escaped Unicode.
It is byte/hash/base64-bound, NOT reserialized with PostgreSQL's UTF-8 JSON
canonicalizer. Only the closed ASCII root transition is canonicalized here.
"""
    _schema_name(namespace)
    bounds = metric_bounds()
    metric_bounds_json = _literal(json.dumps(bounds, sort_keys=True))
    handler_digests = _literal(json.dumps({
        operation: authority_contract.handler_contract_digest(operation)
        for operation in sorted(authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS)
    }, sort_keys=True))
    row_joins = {
        "plannerTransactionId": "planner_transaction_id", "operation": "operation",
        "operationId": "operation_id", "requestDigest": "request_digest",
        "capabilityId": "capability_id", "operationContractDigest": "operation_contract_digest",
        "queryManifestDigest": "query_manifest_digest",
        "selectedBusinessRowsDigest": "selected_business_rows_digest",
        "mutationPlanDigest": "mutation_plan_digest", "workUnits": "work_units",
        "authorityRootSetBeforeDigest": "authority_root_set_before_digest",
        "authorizationProjectionDigest": "authorization_projection_digest",
        "authoritySnapshotDigest": "authority_snapshot_digest",
        "deadlineMonotonicNs": "deadline_monotonic_ns", "deadlineEpochNs": "deadline_epoch_ns",
        "fence": "fence", "sourceRevision": "source_revision",
    }
    joins = "\n OR ".join(
        f"rt_plan->>{_literal(field)} IS DISTINCT FROM planner.{column}::text"
        for field, column in row_joins.items()
    )
    return textwrap.dedent(f"""
        IF planner.plan_protocol IS DISTINCT FROM 'v3'
            OR planner.retained_record_digest IS NOT NULL
            OR ({handler_digests}::pg_catalog.jsonb ? planner.operation) IS NOT TRUE
        THEN RAISE EXCEPTION 'authority root transition requires legacy v3 protocol'; END IF;
        IF planner.exact_plan_base64url IS NULL
            OR planner.exact_plan_base64url !~ '^[A-Za-z0-9_-]+$'
            OR planner.exact_plan_byte_count IS NULL
            OR planner.exact_plan_byte_count NOT BETWEEN 2 AND {authority_contract.MAX_RESULT_BYTES}
            OR pg_catalog.length(planner.exact_plan_base64url) > {4 * ((authority_contract.MAX_RESULT_BYTES + 2) // 3)}
        THEN RAISE EXCEPTION 'authority root transition exact plan bytes are invalid'; END IF;
        rt_plan_bytes := pg_catalog.decode(
            pg_catalog.translate(planner.exact_plan_base64url, '-_', '+/')
            || pg_catalog.repeat('=', (4 - pg_catalog.length(planner.exact_plan_base64url) % 4) % 4),
            'base64');
        IF pg_catalog.octet_length(rt_plan_bytes) IS DISTINCT FROM planner.exact_plan_byte_count
            OR 'sha256:' || pg_catalog.encode(pg_catalog.sha256(rt_plan_bytes), 'hex')
                IS DISTINCT FROM planner.exact_plan_bytes_digest
            OR pg_catalog.translate(pg_catalog.encode(rt_plan_bytes, 'base64'), E'+/=\\n\\r', '-_')
                IS DISTINCT FROM planner.exact_plan_base64url
        THEN RAISE EXCEPTION 'authority root transition exact plan bytes changed'; END IF;
        rt_plan_text := pg_catalog.convert_from(rt_plan_bytes, 'UTF8');
        IF pg_catalog.octet_length(rt_plan_text) <> pg_catalog.length(rt_plan_text)
        THEN RAISE EXCEPTION 'authority root transition plan transport is not ASCII'; END IF;
        rt_payload_json := rt_plan_text::pg_catalog.json;
        IF NOT {_exact_keys('rt_payload_json', _PAYLOAD_FIELDS)}
            OR rt_payload_json->>'schema' IS DISTINCT FROM 'serverware.policyAuthorityPlannerResponse/v3'
        THEN RAISE EXCEPTION 'authority root transition plan payload is not closed v3'; END IF;
        rt_plan_json := rt_payload_json->'measuredPlan';
        IF NOT {_exact_keys('rt_plan_json', _PLAN_FIELDS)}
            OR rt_plan_json->>'schema' IS DISTINCT FROM 'serverware.policyAuthorityMeasuredPlan/v3'
        THEN RAISE EXCEPTION 'authority root transition measured plan is not closed v3'; END IF;
        rt_payload := rt_payload_json::pg_catalog.jsonb;
        rt_plan := rt_plan_json::pg_catalog.jsonb;
        rt_transition_json := rt_payload_json->'rootTransition';
        IF NOT {_exact_keys('rt_transition_json', _TRANSITION_FIELDS)}
            OR rt_transition_json->>'schema' IS DISTINCT FROM {_literal(TRANSITION_SCHEMA)}
            OR rt_transition_json->>'profile' IS DISTINCT FROM {_literal(TRANSITION_PROFILE)}
        THEN RAISE EXCEPTION 'authority root transition profile is not closed'; END IF;
        rt_transition := rt_transition_json::pg_catalog.jsonb;
        FOREACH rt_field IN ARRAY ARRAY['businessBeforeRoots', 'authorizationBeforeRoots',
                                       'businessAfterRoots', 'authorizationAfterRoots'] LOOP
            IF pg_catalog.json_typeof(rt_transition_json->rt_field) IS DISTINCT FROM 'array'
            THEN RAISE EXCEPTION 'authority root transition root vector is not an array'; END IF;
            IF pg_catalog.json_array_length(rt_transition_json->rt_field) > {authority_contract.MAX_QUERY_PROOFS}
            THEN RAISE EXCEPTION 'authority root transition root vector exceeds its bound'; END IF;
            rt_previous_table := NULL;
            FOR rt_root_json IN SELECT value FROM pg_catalog.json_array_elements(rt_transition_json->rt_field) LOOP
                IF NOT {_exact_keys('rt_root_json', _ROOT_FIELDS)}
                    OR pg_catalog.json_typeof(rt_root_json->'table') IS DISTINCT FROM 'string'
                    OR (rt_root_json->>'table') !~ '^[a-z][a-z0-9_]{{0,127}}$'
                    OR pg_catalog.json_typeof(rt_root_json->'rootDigest') IS DISTINCT FROM 'string'
                    OR (rt_root_json->>'rootDigest') !~ '^sha256:[0-9a-f]{{64}}$'
                    OR pg_catalog.json_typeof(rt_root_json->'rootRevision') IS DISTINCT FROM 'number'
                    OR (rt_root_json->>'rootRevision') !~ '^(0|[1-9][0-9]*)$'
                    OR pg_catalog.length(rt_root_json->>'rootRevision') > 19
                    OR pg_catalog.json_typeof(rt_root_json->'leafCount') IS DISTINCT FROM 'number'
                    OR (rt_root_json->>'leafCount') !~ '^(0|[1-9][0-9]*)$'
                    OR pg_catalog.length(rt_root_json->>'leafCount') > 19
                THEN RAISE EXCEPTION 'authority root transition root descriptor is invalid'; END IF;
                IF (rt_root_json->>'rootRevision')::numeric > 9223372036854775807
                    OR (rt_root_json->>'leafCount')::numeric > 9223372036854775807
                    OR (rt_previous_table IS NOT NULL
                        AND (rt_root_json->>'table') COLLATE "C" <= rt_previous_table COLLATE "C")
                THEN RAISE EXCEPTION 'authority root transition root descriptor order or bound changed'; END IF;
                IF ((rt_root_json->>'leafCount')::bigint = 0)
                        IS DISTINCT FROM (rt_root_json->>'rootDigest' = {_literal(empty_digest(0))})
                    OR ((rt_root_json->>'rootRevision')::bigint = 0
                        AND (rt_root_json->>'leafCount')::bigint <> 0)
                THEN RAISE EXCEPTION 'authority root transition empty root binding changed'; END IF;
                rt_previous_table := rt_root_json->>'table';
            END LOOP;
            SELECT COALESCE(pg_catalog.jsonb_agg(value->>'table' ORDER BY ordinality), '[]'::pg_catalog.jsonb)
            INTO rt_table_names
            FROM pg_catalog.jsonb_array_elements(rt_transition->rt_field) WITH ORDINALITY AS item(value, ordinality);
            IF rt_field IN ('businessBeforeRoots', 'businessAfterRoots') THEN
                SELECT COALESCE(pg_catalog.jsonb_agg(table_name ORDER BY table_name COLLATE "C"), '[]'::pg_catalog.jsonb)
                INTO rt_expected_table_names
                FROM {namespace}.policy_authority_query_dependency_manifests WHERE operation = capability.operation;
            ELSE
                SELECT COALESCE(pg_catalog.jsonb_agg(table_name ORDER BY table_name COLLATE "C"), '[]'::pg_catalog.jsonb)
                INTO rt_expected_table_names
                FROM {namespace}.policy_authority_authorization_dependency_manifests WHERE operation = capability.operation;
            END IF;
            IF rt_table_names IS DISTINCT FROM rt_expected_table_names
            THEN RAISE EXCEPTION 'authority root transition root inventory escaped its manifest'; END IF;
        END LOOP;
        IF pg_catalog.jsonb_array_length(rt_transition->'businessBeforeRoots') = 0
            OR pg_catalog.jsonb_array_length(rt_transition->'businessBeforeRoots')
                + pg_catalog.jsonb_array_length(rt_transition->'authorizationBeforeRoots') > {authority_contract.MAX_QUERY_PROOFS}
            OR rt_transition->'authorizationBeforeRoots' IS DISTINCT FROM rt_transition->'authorizationAfterRoots'
            OR EXISTS (
                SELECT 1 FROM pg_catalog.jsonb_array_elements(rt_transition->'businessBeforeRoots') AS business(value)
                JOIN pg_catalog.jsonb_array_elements(rt_transition->'authorizationBeforeRoots') AS auth_root(value)
                    ON business.value->>'table' = auth_root.value->>'table'
            )
        THEN RAISE EXCEPTION 'authority root transition authorization root class changed'; END IF;
        IF EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_array_elements(rt_transition->'businessBeforeRoots') AS before_root(value)
            JOIN pg_catalog.jsonb_array_elements(rt_transition->'businessAfterRoots') AS after_root(value)
                ON before_root.value->>'table' = after_root.value->>'table'
            WHERE (after_root.value->>'rootRevision')::bigint < (before_root.value->>'rootRevision')::bigint
        ) THEN RAISE EXCEPTION 'authority root transition revision moved backward'; END IF;
        IF NOT {_exact_keys("rt_transition_json->'metrics'", tuple(bounds))}
        THEN RAISE EXCEPTION 'authority root transition metrics are not closed'; END IF;
        FOR rt_field IN SELECT pg_catalog.jsonb_object_keys({metric_bounds_json}::pg_catalog.jsonb) LOOP
            IF pg_catalog.json_typeof(rt_transition_json->'metrics'->rt_field) IS DISTINCT FROM 'number'
                OR (rt_transition_json->'metrics'->>rt_field) !~ '^(0|[1-9][0-9]*)$'
                OR pg_catalog.length(rt_transition_json->'metrics'->>rt_field) > 19
            THEN RAISE EXCEPTION 'authority root transition metric is not an unsigned integer'; END IF;
            IF (rt_transition_json->'metrics'->>rt_field)::numeric
                > ({metric_bounds_json}::pg_catalog.jsonb->>rt_field)::numeric
            THEN RAISE EXCEPTION 'authority root transition metric exceeds its profile'; END IF;
        END LOOP;
        IF pg_catalog.jsonb_typeof(rt_payload->'selectedBusinessRows') IS DISTINCT FROM 'array'
            OR pg_catalog.jsonb_typeof(rt_payload->'mutationPlan') IS DISTINCT FROM 'array'
            OR pg_catalog.jsonb_typeof(rt_payload->'queryMultiproofs') IS DISTINCT FROM 'array'
        THEN RAISE EXCEPTION 'authority root transition measured sets are not arrays'; END IF;
        IF (rt_transition->'metrics'->>'selectedRows')::bigint
                <> pg_catalog.jsonb_array_length(rt_payload->'selectedBusinessRows')
            OR (rt_transition->'metrics'->>'mutations')::bigint
                <> pg_catalog.jsonb_array_length(rt_payload->'mutationPlan')
            OR pg_catalog.jsonb_array_length(rt_payload->'queryMultiproofs')
                <> pg_catalog.jsonb_array_length(rt_payload->'selectedBusinessRows')
            OR (rt_transition->'metrics'->>'mutations')::bigint
                > (rt_transition->'metrics'->>'selectedRows')::bigint
            OR (rt_transition->'metrics'->>'proofVectors')::bigint
                <> (rt_transition->'metrics'->>'selectedRows')::bigint * 64
            OR (rt_transition->'metrics'->>'proofChildSlots')::bigint
                <> (rt_transition->'metrics'->>'proofVectors')::bigint * 16
            OR (rt_transition->'metrics'->>'recomputedAncestors')::bigint
                > (rt_transition->'metrics'->>'mutations')::bigint * 64
            OR (rt_transition->'metrics'->>'hashWork')::bigint < 66
            OR (rt_transition->'metrics'->>'inputBytes')::bigint < 1
            OR (rt_transition->'metrics'->>'jsonNodes')::bigint < 1
            OR rt_payload->'selectedBusinessRows' IS DISTINCT FROM planner.selected_business_rows_json::pg_catalog.jsonb
            OR rt_payload->'mutationPlan' IS DISTINCT FROM planner.mutation_plan_json::pg_catalog.jsonb
        THEN RAISE EXCEPTION 'authority root transition measured set or metric binding changed'; END IF;
        FOREACH rt_field IN ARRAY ARRAY['workUnits', 'authoritySchemaVersion', 'deadlineMonotonicNs', 'deadlineEpochNs', 'fence'] LOOP
            IF pg_catalog.json_typeof(rt_plan_json->rt_field) IS DISTINCT FROM 'number'
                OR (rt_plan_json->>rt_field) !~ '^[1-9][0-9]*$'
                OR pg_catalog.length(rt_plan_json->>rt_field) > 19
            THEN RAISE EXCEPTION 'authority root transition plan counter is invalid'; END IF;
        END LOOP;
        IF {joins}
            OR rt_plan->>'sourceRevision' IS DISTINCT FROM {_literal(authority_contract.SOURCE_REVISION)}
            OR rt_plan->>'authoritySchemaVersion' IS DISTINCT FROM '{authority_contract.SCHEMA_VERSION}'
            OR rt_plan->>'operationManifestDigest' IS DISTINCT FROM {_literal(authority_contract.OPERATION_MANIFEST_DIGEST)}
            OR rt_plan->>'operationContractDigest' IS DISTINCT FROM {_literal(authority_contract.OPERATION_MANIFEST_DIGEST)}
            OR rt_plan->>'handlerContractDigest' IS DISTINCT FROM
                ({handler_digests}::pg_catalog.jsonb->>capability.operation)
            OR rt_plan->>'capabilityId' IS DISTINCT FROM capability.capability_id
            OR rt_plan->>'plannerTransactionId' IS DISTINCT FROM capability.planner_transaction_id
            OR rt_plan->>'operation' IS DISTINCT FROM capability.operation
            OR rt_plan->>'operationId' IS DISTINCT FROM capability.operation_id
            OR rt_plan->>'requestDigest' IS DISTINCT FROM capability.request_digest
            OR rt_plan->>'authorityRootSetBeforeDigest' IS DISTINCT FROM capability.authority_root_set_digest
            OR rt_plan->>'queryManifestDigest' IS DISTINCT FROM capability.query_manifest_digest
            OR rt_plan->>'selectedBusinessRowsDigest' IS DISTINCT FROM capability.selected_business_rows_digest
            OR rt_plan->>'mutationPlanDigest' IS DISTINCT FROM capability.mutation_plan_digest
            OR rt_plan->>'authorizationProjectionDigest' IS DISTINCT FROM capability.authorization_projection_digest
            OR rt_payload->>'expectedResultDigest' IS DISTINCT FROM capability.expected_result_digest
        THEN RAISE EXCEPTION 'authority root transition locked plan binding changed'; END IF;
        IF NOT {_exact_keys("rt_payload_json->'plannerIdentity'", ('sessionIdentityDigest', 'measurementDigest', 'attestationReceiptDigest'))}
            OR rt_payload->'plannerIdentity'->>'sessionIdentityDigest'
                IS DISTINCT FROM planner.planner_session_identity_digest
            OR rt_payload->'plannerIdentity'->>'measurementDigest'
                IS DISTINCT FROM planner.planner_measurement_digest
            OR rt_payload->'plannerIdentity'->>'attestationReceiptDigest'
                IS DISTINCT FROM planner.planner_attestation_receipt_digest
        THEN RAISE EXCEPTION 'authority root transition planner identity changed'; END IF;
        rt_transition_digest := {namespace}.serverware_policy_authority_domain_digest(
            {_literal(TRANSITION_SCHEMA)}, {namespace}.serverware_policy_authority_wire_json(rt_transition));
        IF rt_plan->>'rootTransitionDigest' IS DISTINCT FROM rt_transition_digest
        THEN RAISE EXCEPTION 'authority root transition digest changed'; END IF;
        rt_snapshot_digest := {namespace}.serverware_policy_authority_domain_digest(
            'serverware.policyAuthoritySnapshot/v3', planner.operation, planner.operation_id,
            planner.request_digest, planner.query_manifest_digest, planner.authority_root_set_before_digest,
            planner.authorization_projection_digest, planner.selected_business_rows_digest,
            planner.mutation_plan_digest, rt_transition_digest);
        IF rt_snapshot_digest IS DISTINCT FROM planner.authority_snapshot_digest
            OR rt_snapshot_digest IS DISTINCT FROM capability.authority_snapshot_digest
            OR rt_snapshot_digest IS DISTINCT FROM rt_plan->>'authoritySnapshotDigest'
        THEN RAISE EXCEPTION 'authority root transition snapshot binding changed'; END IF;
        rt_expected_after_digest := {namespace}.serverware_policy_authority_domain_digest(
            'serverware.policyAuthorityRootSet/v1',
            {namespace}.serverware_policy_authority_wire_json(rt_transition->'businessAfterRoots'));
        rt_expected_authorization_after_digest := {namespace}.serverware_policy_authority_domain_digest(
            'serverware.policyAuthorityAuthorizationRootSet/v1',
            {namespace}.serverware_policy_authority_wire_json(rt_transition->'authorizationAfterRoots'));
    """)


def assert_root_transition_before_sql(namespace: str) -> str:
    """Join supplied before heads to the exact locked business/auth root reads."""
    _schema_name(namespace)
    return """
        IF rt_transition->'businessBeforeRoots' IS DISTINCT FROM
                COALESCE(root_set_before_json, '[]')::pg_catalog.jsonb
            OR rt_transition->'authorizationBeforeRoots' IS DISTINCT FROM
                COALESCE(authorization_root_set_json, '[]')::pg_catalog.jsonb
        THEN RAISE EXCEPTION 'authority root transition before roots changed'; END IF;
    """


def assert_root_transition_payload_sql(namespace: str) -> str:
    """Bind decoded payloads while retaining their original canonical wire bytes.

    Rendering is only an equality oracle here. It never replaces a received
    request/result or changes their persisted byte hash. JSONB value equality
    alone would erase duplicate members, whitespace and alternate escapes.
    """
    _schema_name(namespace)
    return textwrap.dedent(f"""
        canonical_result := {namespace}.serverware_policy_authority_wire_json(
            pg_catalog.convert_from(result_bytes, 'UTF8')::pg_catalog.jsonb);
        IF rt_payload->'typedRequest' IS DISTINCT FROM
                pg_catalog.convert_from(request_bytes, 'UTF8')::pg_catalog.jsonb
            OR rt_payload->'expectedResult' IS DISTINCT FROM
                pg_catalog.convert_from(result_bytes, 'UTF8')::pg_catalog.jsonb
            OR rt_payload->'authorizationProjection' IS DISTINCT FROM
                authorization_projection.projection_json::pg_catalog.jsonb
        THEN RAISE EXCEPTION 'authority root transition exact payload changed'; END IF;
        IF pg_catalog.convert_to(canonical_result, 'UTF8') IS DISTINCT FROM result_bytes
            OR pg_catalog.convert_to({namespace}.serverware_policy_authority_wire_json(
                pg_catalog.convert_from(request_bytes, 'UTF8')::pg_catalog.jsonb), 'UTF8')
                IS DISTINCT FROM request_bytes
            OR supplied_exact_request_base64url IS DISTINCT FROM
                execution_envelope.exact_request_base64url
            OR pg_catalog.octet_length(request_bytes) IS DISTINCT FROM
                execution_envelope.exact_request_byte_count
            OR 'sha256:' || pg_catalog.encode(pg_catalog.sha256(request_bytes), 'hex')
                IS DISTINCT FROM execution_envelope.exact_request_bytes_digest
        THEN RAISE EXCEPTION 'authority v9 exact request or result bytes changed'; END IF;
    """)


def assert_root_transition_after_sql(namespace: str) -> str:
    """Compare all actual after heads before any terminal publication/consumption."""
    _schema_name(namespace)
    return textwrap.dedent(f"""
        SELECT {namespace}.serverware_policy_authority_wire_json(
            COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'table', roots.table_name, 'rootRevision', roots.root_revision,
                'rootDigest', roots.root_digest, 'leafCount', roots.leaf_count
            ) ORDER BY roots.table_name COLLATE "C"), '[]'::pg_catalog.jsonb))
        INTO rt_actual_authorization_after_json
        FROM {namespace}.policy_authority_authenticated_table_roots AS roots
        WHERE roots.table_name IN (
            SELECT table_name FROM {namespace}.policy_authority_authorization_dependency_manifests
            WHERE operation = capability.operation);
        IF rt_transition->'businessAfterRoots' IS DISTINCT FROM
                COALESCE(root_set_after_json, '[]')::pg_catalog.jsonb
            OR rt_expected_after_digest IS DISTINCT FROM root_set_after_digest
            OR rt_transition->'authorizationAfterRoots' IS DISTINCT FROM
                rt_actual_authorization_after_json::pg_catalog.jsonb
            OR rt_expected_authorization_after_digest IS DISTINCT FROM
                {namespace}.serverware_policy_authority_domain_digest(
                    'serverware.policyAuthorityAuthorizationRootSet/v1', rt_actual_authorization_after_json)
        THEN RAISE EXCEPTION 'authority root transition after roots changed'; END IF;
    """)


def assert_root_transition_replay_sql(namespace: str) -> str:
    """Bind historical terminal data, never compare it to current mutable heads."""
    _schema_name(namespace)
    return """
        IF execution_envelope.terminal_receipt_json::pg_catalog.jsonb->>'authoritySnapshotDigest'
                IS DISTINCT FROM rt_snapshot_digest
            OR execution_envelope.terminal_receipt_json::pg_catalog.jsonb->>'authorityRootSetBeforeDigest'
                IS DISTINCT FROM planner.authority_root_set_before_digest
            OR execution_envelope.terminal_receipt_json::pg_catalog.jsonb->>'authorityRootSetAfterDigest'
                IS DISTINCT FROM rt_expected_after_digest
        THEN RAISE EXCEPTION 'authority root transition historical receipt changed'; END IF;
    """
