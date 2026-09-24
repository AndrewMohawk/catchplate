"""Private SQL integrity binding of the original retained revocation-v4 bytes.

The caller supplies an already locked ``planner`` row. These fragments read
its immutable sidecar and expose data, not verification or execution tokens.
They do not verify signatures/proofs, enroll stored keys, refresh historical
context, read current roots, reserve authority or install an entrypoint. The
active v3 executor remains separate. SQL parsing/encoding is not Python H/B/N
work; byte bounds and bounded post-parse walks are not process-memory bounds.
"""
from __future__ import annotations

import textwrap

from serverware import authority_contract as authority
from serverware import authority_index_contract as counted
from serverware import authority_index_projection as projection
from serverware import authority_revocation_bundle_contract as bundle
from serverware import authority_revocation_plan_contract as plan
from serverware import authority_revocation_retention as retention
from serverware import authority_root_transition as primary
from serverware.authority_store.mutation_sql import _schema_name


def _literal(value):
    return "'" + value.replace("'", "''") + "'"


def _closed(expression, fields):
    expected = ", ".join(_literal(field) for field in sorted(fields))
    return f"""(CASE WHEN pg_catalog.jsonb_typeof({expression}) IS DISTINCT FROM 'object'
        THEN FALSE ELSE (SELECT pg_catalog.array_agg(key ORDER BY key COLLATE "C")
        FROM pg_catalog.jsonb_object_keys({expression}) AS key)
        IS NOT DISTINCT FROM ARRAY[{expected}]::text[] END)"""


def _wire(namespace, value, output, *, size, nodes=plan.MAX_JSON_NODES, depth=plan.MAX_JSON_DEPTH):
    # Every expression/name is source-fixed by this module, never caller SQL.
    return f"""
        SELECT * INTO STRICT rv_measured FROM {namespace}.serverware_policy_authority_wire_walk(
            {value}, {depth}, {nodes}, {size}, FALSE);
        SELECT * INTO STRICT rv_rendered FROM {namespace}.serverware_policy_authority_wire_walk(
            {value}, {depth}, rv_measured.visited_nodes, rv_measured.emitted_bytes, TRUE);
        IF rv_rendered.visited_nodes IS DISTINCT FROM rv_measured.visited_nodes
            OR rv_rendered.emitted_bytes IS DISTINCT FROM rv_measured.emitted_bytes
            OR pg_catalog.octet_length(rv_rendered.rendered) IS DISTINCT FROM rv_measured.emitted_bytes
        THEN RAISE EXCEPTION 'revocation retained wire measurement changed'; END IF;
        {output} := rv_rendered.rendered;
    """


def _transport(namespace, label, row, encoded, count, digest, maximum, *, nodes, depth):
    prefix = "rv_" + label
    return f"""
        IF {row}.{encoded} IS NULL OR {row}.{count} IS NULL OR {row}.{digest} IS NULL
            OR {row}.{count} NOT BETWEEN 2 AND {maximum}
            OR {row}.{digest} COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
            OR pg_catalog.length({row}.{encoded})::bigint <> (4 * {row}.{count} + 2) / 3
            OR {row}.{encoded} COLLATE "C" !~ '^[A-Za-z0-9_-]+$'
        THEN RAISE EXCEPTION 'revocation retained {label} transport is invalid'; END IF;
        {prefix}_bytes := pg_catalog.decode(pg_catalog.translate({row}.{encoded}, '-_', '+/')
            || pg_catalog.repeat('=', (4 - pg_catalog.length({row}.{encoded}) % 4) % 4), 'base64');
        IF pg_catalog.octet_length({prefix}_bytes) IS DISTINCT FROM {row}.{count}
            OR 'sha256:' || pg_catalog.encode(pg_catalog.sha256({prefix}_bytes), 'hex')
                IS DISTINCT FROM {row}.{digest}
            OR pg_catalog.translate(pg_catalog.encode({prefix}_bytes, 'base64'), E'+/=\\n\\r', '-_')
                IS DISTINCT FROM {row}.{encoded}
        THEN RAISE EXCEPTION 'revocation retained {label} bytes changed'; END IF;
        {prefix}_text := pg_catalog.convert_from({prefix}_bytes, 'UTF8');
        IF pg_catalog.octet_length({prefix}_text) IS DISTINCT FROM pg_catalog.length({prefix}_text)
        THEN RAISE EXCEPTION 'revocation retained {label} transport is not ASCII'; END IF;
        {prefix} := {prefix}_text::pg_catalog.jsonb;
        {_wire(namespace, prefix, 'rv_canonical', size=maximum, nodes=nodes, depth=depth)}
        IF pg_catalog.convert_to(rv_canonical, 'UTF8') IS DISTINCT FROM {prefix}_bytes
        THEN RAISE EXCEPTION 'revocation retained {label} bytes are not canonical'; END IF;
    """


def _integers(expression, fields, *, minimum=1):
    names = ", ".join(_literal(name) for name in fields)
    pattern = "^-?(0|[1-9][0-9]*)$" if minimum < 0 else "^(0|[1-9][0-9]*)$"
    return f"""
        FOREACH rv_field IN ARRAY ARRAY[{names}] LOOP
            IF pg_catalog.jsonb_typeof({expression}->rv_field) IS DISTINCT FROM 'number'
                OR ({expression}->>rv_field) COLLATE "C" !~ '{pattern}'
                OR pg_catalog.length({expression}->>rv_field) > 20
            THEN RAISE EXCEPTION 'revocation retained counter type is invalid'; END IF;
            IF ({expression}->>rv_field)::numeric NOT BETWEEN {minimum} AND 9223372036854775807
            THEN RAISE EXCEPTION 'revocation retained counter bound is invalid'; END IF;
        END LOOP;
    """


def revocation_retained_declarations_sql() -> str:
    return """
        rv_retained record;
        rv_measured record;
        rv_rendered record;
        rv_payload_bytes bytea;
        rv_envelope_bytes bytea;
        rv_context_bytes bytea;
        rv_payload_text text;
        rv_envelope_text text;
        rv_context_text text;
        rv_payload pg_catalog.jsonb;
        rv_envelope pg_catalog.jsonb;
        rv_context pg_catalog.jsonb;
        rv_plan pg_catalog.jsonb;
        rv_transition pg_catalog.jsonb;
        rv_primary pg_catalog.jsonb;
        rv_header pg_catalog.jsonb;
        rv_canonical text;
        rv_transition_text text;
        rv_field text;
        rv_record_digest text;
        rv_snapshot_digest text;
        rv_frame text;
        rv_frame_bytes bytea;
        rv_snapshot_material bytea;
        rv_signature bytea;
    """


def load_revocation_retained_sql(namespace: str) -> str:
    """Bind a locked parent to its original transports and v4 commitments.

    The result establishes consistency only. In particular a newly forged
    signature with correspondingly changed hashes is not rejected as a false
    signature here. Independent genuine replay remains mandatory at the future
    execution consumer; none of its trusted inputs may come from these claims.
    """
    _schema_name(namespace)
    joins = {
        "plannerTransactionId": "planner_transaction_id", "operation": "operation",
        "operationId": "operation_id", "requestDigest": "request_digest", "capabilityId": "capability_id",
        "sourceRevision": "source_revision", "operationContractDigest": "operation_contract_digest",
        "queryManifestDigest": "query_manifest_digest", "selectedBusinessRowsDigest": "selected_business_rows_digest",
        "mutationPlanDigest": "mutation_plan_digest", "workUnits": "work_units",
        "authorityRootSetBeforeDigest": "authority_root_set_before_digest",
        "authorizationProjectionDigest": "authorization_projection_digest",
        "authoritySnapshotDigest": "authority_snapshot_digest", "deadlineMonotonicNs": "deadline_monotonic_ns",
        "deadlineEpochNs": "deadline_epoch_ns", "fence": "fence",
    }
    plan_joins = "\n OR ".join(f"rv_plan->>{_literal(name)} IS DISTINCT FROM planner.{column}::text"
                               for name, column in joins.items())
    context_joins = "\n OR ".join(f"rv_context->>{_literal(name)} IS DISTINCT FROM planner.{column}::text"
        for name, column in (("expectedPlannerTransactionId", "planner_transaction_id"),
            ("expectedCapabilityId", "capability_id"), ("expectedFence", "fence"),
            ("reservedAtEpochNs", "reserved_at_epoch_ns"), ("deadlineEpochNs", "deadline_epoch_ns"),
            ("deadlineMonotonicNs", "deadline_monotonic_ns")))
    snapshots = ", ".join("rv_plan->>" + _literal(name) for name in plan.SNAPSHOT_FRAME_FIELDS)
    digest_fields = ", ".join(_literal(name) for name in sorted(plan.PLAN_DIGEST_FIELDS))
    payload_digests = "".join(f"""
        {_wire(namespace, 'rv_payload->' + _literal(name), 'rv_canonical', size=plan.MAX_PAYLOAD_BYTES)}
        IF {target} IS DISTINCT FROM {namespace}.serverware_policy_authority_domain_digest(
                {_literal(domain)}, rv_canonical)
        THEN RAISE EXCEPTION 'revocation retained {name} commitment changed'; END IF;
        {('IF rv_canonical IS DISTINCT FROM planner.' + column + " THEN RAISE EXCEPTION 'revocation retained parent JSON changed'; END IF;") if column else ''}
    """ for name, target, domain, column in (
        ("selectedBusinessRows", "planner.selected_business_rows_digest", "serverware.policyAuthoritySelectedBusinessRows/v1", "selected_business_rows_json"),
        ("mutationPlan", "planner.mutation_plan_digest", "serverware.policyAuthorityMutationPlan/v3", "mutation_plan_json"),
        ("authorizationProjection", "planner.authorization_projection_digest", "serverware.policyAuthorityAuthorizationProjection/v1", None),
        ("webauthnEvidence", "rv_payload->'authorizationProjection'->>'assertionEvidenceDigest'", "serverware.policyAuthorityWebAuthnAssertionEvidence/v1", None),
        ("expectedResult", "rv_payload->>'expectedResultDigest'", "serverware.policyAuthorityControlledWriterResult/v2", None),
        ("revocationProofBundle", "rv_transition->>'proofBundleDigest'", bundle.BUNDLE_SCHEMA, None),
    ))
    return textwrap.dedent(f"""
        IF planner.plan_protocol IS DISTINCT FROM {_literal(retention.PLAN_PROTOCOL)}
            OR planner.source_revision IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
            OR planner.operation IS DISTINCT FROM {_literal(plan.OPERATION)}
            OR planner.status IS NULL OR planner.status NOT IN ('planned', 'consumed')
            OR planner.retained_record_digest IS NULL
            OR planner.retained_record_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
        THEN RAISE EXCEPTION 'revocation retained parent is not planned v4'; END IF;
        SELECT * INTO STRICT rv_retained
        FROM {namespace}.policy_authority_revocation_retained_plans
        WHERE planner_transaction_id = planner.planner_transaction_id;
        IF rv_retained.planner_transaction_id IS DISTINCT FROM planner.planner_transaction_id
            OR rv_retained.plan_protocol IS DISTINCT FROM planner.plan_protocol
            OR rv_retained.source_revision IS DISTINCT FROM planner.source_revision
            OR rv_retained.retained_record_digest IS DISTINCT FROM planner.retained_record_digest
            OR rv_retained.planner_key_digest IS NULL OR rv_retained.verifier_key_digest IS NULL
            OR rv_retained.planner_key_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
            OR rv_retained.verifier_key_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
        THEN RAISE EXCEPTION 'revocation retained parent sidecar binding changed'; END IF;
        {_transport(namespace, 'payload', 'planner', 'exact_plan_base64url', 'exact_plan_byte_count', 'exact_plan_bytes_digest', plan.MAX_PAYLOAD_BYTES, nodes=plan.MAX_JSON_NODES, depth=plan.MAX_JSON_DEPTH)}
        {_transport(namespace, 'envelope', 'rv_retained', 'exact_envelope_base64url', 'exact_envelope_byte_count', 'exact_envelope_bytes_digest', plan.MAX_PAYLOAD_BYTES, nodes=plan.MAX_JSON_NODES, depth=plan.MAX_JSON_DEPTH)}
        {_transport(namespace, 'context', 'rv_retained', 'evaluation_context_base64url', 'evaluation_context_byte_count', 'evaluation_context_bytes_digest', retention.MAX_CONTEXT_BYTES, nodes=retention.MAX_CONTEXT_NODES, depth=retention.MAX_CONTEXT_DEPTH)}
        IF NOT {_closed('rv_envelope', plan.SIGNED_ENVELOPE_FIELDS)}
            OR rv_envelope->>'schema' IS DISTINCT FROM {_literal(plan.SIGNED_MEASURED_PLAN_SCHEMA)}
            OR rv_envelope->'payload' IS DISTINCT FROM rv_payload
            OR pg_catalog.jsonb_typeof(rv_envelope->'signatureBase64Url') IS DISTINCT FROM 'string'
            OR pg_catalog.length(rv_envelope->>'signatureBase64Url') IS DISTINCT FROM 86
            OR (rv_envelope->>'signatureBase64Url') COLLATE "C" !~ '^[A-Za-z0-9_-]{{86}}$'
        THEN RAISE EXCEPTION 'revocation retained envelope is not closed v4'; END IF;
        rv_signature := pg_catalog.decode(pg_catalog.translate(rv_envelope->>'signatureBase64Url', '-_', '+/') || '==', 'base64');
        IF pg_catalog.octet_length(rv_signature) IS DISTINCT FROM 64
            OR pg_catalog.translate(pg_catalog.encode(rv_signature, 'base64'), E'+/=\\n\\r', '-_')
                IS DISTINCT FROM rv_envelope->>'signatureBase64Url'
        THEN RAISE EXCEPTION 'revocation retained signature transport changed'; END IF;
        IF NOT {_closed('rv_payload', plan.PAYLOAD_FIELDS)}
            OR rv_payload->>'schema' IS DISTINCT FROM {_literal(plan.PLANNER_RESPONSE_SCHEMA)}
            OR NOT {_closed("rv_payload->'measuredPlan'", plan.MEASURED_PLAN_FIELDS)}
            OR rv_payload->'measuredPlan'->>'schema' IS DISTINCT FROM {_literal(plan.MEASURED_PLAN_SCHEMA)}
            OR NOT {_closed('rv_context', retention._CONTEXT_FIELDS)}
            OR rv_context->>'schema' IS DISTINCT FROM {_literal(retention.CONTEXT_SCHEMA)}
            OR rv_context->>'sourceRevision' IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
        THEN RAISE EXCEPTION 'revocation retained payload or context is not closed v4'; END IF;
        rv_plan := rv_payload->'measuredPlan';
        rv_transition := rv_payload->'rootTransition';
        rv_primary := rv_transition->'primaryTransition';
        {_integers('rv_plan', ('workUnits', 'authoritySchemaVersion', 'deadlineMonotonicNs', 'deadlineEpochNs', 'fence'))}
        FOREACH rv_field IN ARRAY ARRAY[{digest_fields}] LOOP
            IF pg_catalog.jsonb_typeof(rv_plan->rv_field) IS DISTINCT FROM 'string'
                OR (rv_plan->>rv_field) COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
            THEN RAISE EXCEPTION 'revocation retained plan digest is invalid'; END IF;
        END LOOP;
        IF {plan_joins}
            OR rv_plan->>'authoritySchemaVersion' IS DISTINCT FROM '{authority.SCHEMA_VERSION}'
            OR rv_plan->>'operationManifestDigest' IS DISTINCT FROM {_literal(authority.OPERATION_MANIFEST_DIGEST)}
            OR rv_plan->>'operationContractDigest' IS DISTINCT FROM {_literal(authority.OPERATION_MANIFEST_DIGEST)}
            OR rv_plan->>'handlerContractDigest' IS DISTINCT FROM {_literal(authority.handler_contract_digest(plan.OPERATION))}
        THEN RAISE EXCEPTION 'revocation retained locked plan binding changed'; END IF;
        IF NOT {_closed("rv_payload->'plannerIdentity'", plan.IDENTITY_FIELDS)}
            OR rv_payload->'plannerIdentity' IS DISTINCT FROM rv_context->'expectedPlannerIdentity'
            OR rv_payload->'plannerIdentity'->>'sessionIdentityDigest' IS DISTINCT FROM planner.planner_session_identity_digest
            OR rv_payload->'plannerIdentity'->>'measurementDigest' IS DISTINCT FROM planner.planner_measurement_digest
            OR rv_payload->'plannerIdentity'->>'attestationReceiptDigest' IS DISTINCT FROM planner.planner_attestation_receipt_digest
            OR NOT {_closed("rv_context->'expectedVerifierIdentity'", plan.IDENTITY_FIELDS)}
            OR NOT {_closed("rv_context->'expectedBefore'", ('businessBeforeRoots', 'authorizationBeforeRoots', 'indexBeforeHeads'))}
            OR {context_joins}
        THEN RAISE EXCEPTION 'revocation retained historical identity changed'; END IF;
        {_integers('rv_context', ('expectedFence', 'reservedAtEpochNs', 'deadlineEpochNs', 'deadlineMonotonicNs', 'nowEpochNs', 'nowMonotonicNs', 'maximumAssertionAgeNs', 'maximumPlanAgeNs'))}
        {_integers('rv_context', ('maximumClockSkewNs',), minimum=0)}
        {_integers('rv_context', ('databaseCutoffUs',), minimum=-(2**63))}
        IF planner.planned_at_epoch_ns IS NULL
            OR planner.planned_at_epoch_ns < planner.reserved_at_epoch_ns
            OR planner.planned_at_epoch_ns >= planner.deadline_epoch_ns
        THEN RAISE EXCEPTION 'revocation retained original planned time changed'; END IF;
        IF NOT {_closed('rv_transition', bundle.TRANSITION_FIELDS)}
            OR rv_transition->>'schema' IS DISTINCT FROM {_literal(bundle.TRANSITION_SCHEMA)}
            OR rv_transition->>'profile' IS DISTINCT FROM {_literal(bundle.TRANSITION_PROFILE)}
            OR rv_transition->>'sourceRevision' IS DISTINCT FROM planner.source_revision
            OR rv_transition->>'operation' IS DISTINCT FROM planner.operation
            OR rv_transition->>'requestDigest' IS DISTINCT FROM planner.request_digest
            OR rv_transition->'cutoffUs' IS DISTINCT FROM rv_context->'databaseCutoffUs'
            OR rv_transition->>'countedProfile' IS DISTINCT FROM {_literal(counted.PROFILE)}
            OR rv_transition->>'projectionManifestDigest' IS DISTINCT FROM {_literal(projection.projection_manifest_digest())}
            OR NOT {_closed('rv_primary', primary.TRANSITION_FIELDS)}
            OR rv_primary->>'schema' IS DISTINCT FROM {_literal(primary.TRANSITION_SCHEMA)}
            OR rv_primary->>'profile' IS DISTINCT FROM {_literal(primary.TRANSITION_PROFILE)}
            OR rv_context->'expectedBefore'->'businessBeforeRoots' IS DISTINCT FROM rv_primary->'businessBeforeRoots'
            OR rv_context->'expectedBefore'->'authorizationBeforeRoots' IS DISTINCT FROM rv_primary->'authorizationBeforeRoots'
            OR rv_context->'expectedBefore'->'indexBeforeHeads' IS DISTINCT FROM rv_transition->'indexBeforeHeads'
            OR NOT {_closed("rv_payload->'revocationProofBundle'", bundle.BUNDLE_FIELDS)}
            OR rv_payload->'revocationProofBundle'->>'schema' IS DISTINCT FROM {_literal(bundle.BUNDLE_SCHEMA)}
            OR rv_payload->'revocationProofBundle'->>'profile' IS DISTINCT FROM {_literal(bundle.BUNDLE_PROFILE)}
            OR rv_payload->'revocationProofBundle'->>'sourceRevision' IS DISTINCT FROM planner.source_revision
            OR NOT {_closed("rv_payload->'revocationProofBundle'->'inputs'", bundle.INPUT_FIELDS)}
        THEN RAISE EXCEPTION 'revocation retained mixed transition binding changed'; END IF;
        {_wire(namespace, 'rv_transition', 'rv_transition_text', size=bundle.MAX_COMPACT_BYTES, nodes=bundle.MAX_COMPACT_NODES)}
        IF rv_plan->>'rootTransitionDigest' IS DISTINCT FROM
            {namespace}.serverware_policy_authority_domain_digest({_literal(bundle.TRANSITION_SCHEMA)}, rv_transition_text)
        THEN RAISE EXCEPTION 'revocation retained mixed transition commitment changed'; END IF;
        IF NOT {_closed("rv_payload->'authorizationProjection'", plan.AUTHORIZATION_PROJECTION_FIELDS)}
            OR NOT {_closed("rv_payload->'webauthnEvidence'", plan.EVIDENCE_FIELDS)}
            OR rv_context->'expectedApproverPolicyDigest' IS DISTINCT FROM rv_payload->'authorizationProjection'->'approverPolicyDigest'
            OR rv_payload->'authorizationProjection'->>'plannerTransactionId' IS DISTINCT FROM planner.planner_transaction_id
        THEN RAISE EXCEPTION 'revocation retained authorization binding changed'; END IF;
        FOREACH rv_field IN ARRAY ARRAY['operation', 'operationId', 'requestDigest', 'capabilityId'] LOOP
            IF rv_payload->'authorizationProjection'->rv_field IS DISTINCT FROM rv_plan->rv_field
                OR rv_payload->'webauthnEvidence'->rv_field IS DISTINCT FROM rv_plan->rv_field
            THEN RAISE EXCEPTION 'revocation retained authorization identity changed'; END IF;
        END LOOP;
        FOREACH rv_field IN ARRAY ARRAY['sessionIdentityDigest', 'measurementDigest', 'attestationReceiptDigest'] LOOP
            rv_frame := 'verifier' || pg_catalog.upper(pg_catalog.substr(rv_field, 1, 1)) || pg_catalog.substr(rv_field, 2);
            IF rv_payload->'authorizationProjection'->rv_frame IS DISTINCT FROM rv_context->'expectedVerifierIdentity'->rv_field
                OR rv_payload->'webauthnEvidence'->rv_frame IS DISTINCT FROM rv_context->'expectedVerifierIdentity'->rv_field
            THEN RAISE EXCEPTION 'revocation retained verifier identity changed'; END IF;
        END LOOP;
        {payload_digests}
        -- The existing generic digest helper has a nine-frame exception ONLY
        -- for Snapshot/v3. Keep it unchanged: this is a fixed v4 nine-frame
        -- recipe, not a new general-purpose SQL hash API.
        rv_snapshot_material := pg_catalog.convert_to({_literal(plan.SNAPSHOT_DOMAIN)}, 'UTF8') || pg_catalog.decode('00', 'hex');
        FOREACH rv_frame IN ARRAY ARRAY[{snapshots}] LOOP
            IF rv_frame IS NULL OR pg_catalog.octet_length(rv_frame) NOT BETWEEN 1 AND 128
            THEN RAISE EXCEPTION 'revocation retained snapshot frame is invalid'; END IF;
            rv_frame_bytes := pg_catalog.convert_to(rv_frame, 'UTF8');
            rv_snapshot_material := rv_snapshot_material || pg_catalog.int8send(pg_catalog.octet_length(rv_frame_bytes)::bigint) || rv_frame_bytes;
        END LOOP;
        rv_snapshot_digest := 'sha256:' || pg_catalog.encode(pg_catalog.sha256(rv_snapshot_material), 'hex');
        IF rv_snapshot_digest IS DISTINCT FROM planner.authority_snapshot_digest
            OR rv_snapshot_digest IS DISTINCT FROM rv_plan->>'authoritySnapshotDigest'
        THEN RAISE EXCEPTION 'revocation retained v4 snapshot commitment changed'; END IF;
        rv_header := pg_catalog.jsonb_build_object(
            'schema', {_literal(retention.RECORD_SCHEMA)}, 'sourceRevision', planner.source_revision,
            'planProtocol', planner.plan_protocol, 'plannerTransactionId', planner.planner_transaction_id,
            'operationId', planner.operation_id, 'requestDigest', planner.request_digest, 'capabilityId', planner.capability_id,
            'plannerKeyDigest', rv_retained.planner_key_digest, 'verifierKeyDigest', rv_retained.verifier_key_digest,
            'envelopeDigest', rv_retained.exact_envelope_bytes_digest, 'envelopeByteCount', rv_retained.exact_envelope_byte_count,
            'contextDigest', rv_retained.evaluation_context_bytes_digest, 'contextByteCount', rv_retained.evaluation_context_byte_count);
        {_wire(namespace, 'rv_header', 'rv_canonical', size=4096, nodes=64, depth=2)}
        rv_record_digest := {namespace}.serverware_policy_authority_domain_digest({_literal(retention.RECORD_SCHEMA)}, rv_canonical);
        IF rv_record_digest IS DISTINCT FROM planner.retained_record_digest
            OR rv_record_digest IS DISTINCT FROM rv_retained.retained_record_digest
        THEN RAISE EXCEPTION 'revocation retained record header commitment changed'; END IF;
    """)
