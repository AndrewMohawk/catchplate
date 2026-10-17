"""Fixed retained maintenance packet/stream consistency, never admission.

The protected owner supplies original packet text, its independently held
packet/pending identities, and its already bounded epoch deadline. This body
only parses canonical originals and rejoins their commitments. It verifies no
signature, proof, current root, role, installed catalog or retained step body.
The genuine Python issuer and protected custody establish provenance; the seal
must join actual immutable step rows and the executor must hold current roots.

No tables, functions, grants, connections or transaction boundaries are created
or accessed here. Shared sxe_* codec scratch is isolated in a nested block;
generic aggregate selected/mutation/work arrays are never admitted. SQL parse,
SRF and canonical-wire resources are not Python shared-work or RSS guarantees.
The original signed interval is preserved; only the local deadline narrows.
"""
from __future__ import annotations

from catchplate import authority_challenge_execution_packet as packet
from catchplate.authority_store import primary_tree_sql
from catchplate.authority_store import successor_execution_sql as codecs
from catchplate.authority_store.revocation_retained_sql import _closed, _literal
from catchplate.authority_store.wire_json_sql import WIRE_JSON_MAX_DEPTH, WIRE_JSON_MAX_NODES


admission = packet.admission
authority, authorization = admission.authorization.authority, admission.authorization
plan, grants, stream, vector = admission.plan, admission.grants, admission.streams, admission.vector
HEADER_FIELDS = frozenset({"schema", "sourceRevision", "operation", "operationId", "requestDigest",
    "configurationDigest", "planDigest", "manifestDigest", "beforeVectorDigest", "afterVectorDigest",
    "resultDigest", "stepCount", "totalBodyBytes", "chainDigest", "steps"})


def declarations_sql() -> str:
    """Four original inputs and held scalar/vector outputs, all cxe_* locals."""
    return """
        cxe_packet_json text; cxe_packet_digest text; cxe_pending_decision_digest text;
        cxe_deadline_epoch_ns bigint;
        cxe_packet jsonb; cxe_stream jsonb; cxe_stream_json text;
        cxe_before_vector_json text; cxe_after_vector_json text; cxe_result_json text;
        cxe_marker jsonb; cxe_issued bigint; cxe_expires bigint;
    """


def _live_sql():
    return """
        IF cxe_deadline_epoch_ns IS NULL OR cxe_deadline_epoch_ns <= 0
            OR pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000000)
                >= cxe_deadline_epoch_ns
        THEN RAISE EXCEPTION 'maintenance packet original processing deadline expired'; END IF;
    """


def _frame_sql(namespace, expression, maximum, text_target, value_target, *, nodes, depth):
    """Source-only identifiers/limits; reuse the exact bounded raw-frame codec."""
    return f"""
        sxe_frame := {expression}; sxe_maximum := {maximum};
        {codecs._frame()}
        IF sxe_total > {packet.MAX_BYTES}
        THEN RAISE EXCEPTION 'maintenance decoded originals exceed eight MiB'; END IF;
        {text_target} := pg_catalog.convert_from(sxe_raw, 'UTF8');
        IF pg_catalog.length({text_target}) IS DISTINCT FROM pg_catalog.octet_length({text_target})
        THEN RAISE EXCEPTION 'maintenance original is not canonical ASCII'; END IF;
        {value_target} := {text_target}::pg_catalog.jsonb;
        {codecs._wire(namespace, value_target, 'cxe_canonical', maximum, nodes, depth)}
        IF cxe_canonical COLLATE "C" IS DISTINCT FROM {text_target} COLLATE "C"
        THEN RAISE EXCEPTION 'maintenance original JSON spelling differs'; END IF;
    """


def _originals_sql(namespace):
    domains = {
        "currentRootEnrollment": authorization.ENROLLMENT_IDENTITY_DOMAIN,
        "grantEnrollment": grants.ENROLLMENT_IDENTITY_DOMAIN,
        "grant": grants.GRANT_IDENTITY_DOMAIN,
        "reserveRequest": authorization.REQUEST_IDENTITY_DOMAIN,
        "reserveReceipt": authorization.RECEIPT_IDENTITY_DOMAIN,
        "computationSnapshot": admission.pending.computation.SNAPSHOT_DOMAIN,
    }
    result = f"""
        IF NOT {_closed("cxe_packet->'originals'", packet.ORIGINAL_FIELDS)}
        THEN RAISE EXCEPTION 'maintenance original inventory differs'; END IF;
        cxe_documents := '{{}}'::jsonb; cxe_identities := '{{}}'::jsonb;
    """
    for name, maximum in packet.CONTROL_MAXIMA:
        nodes, depth = authorization.MAX_NODES, authorization.MAX_DEPTH
        if name in ("grantEnrollment", "grant"):
            nodes, depth = grants.MAX_NODES, grants.MAX_DEPTH
        elif name == "computationSnapshot":
            nodes, depth = admission.pending.computation.MAX_SNAPSHOT_NODES, 4
        result += _frame_sql(namespace, "cxe_packet->'originals'->" + _literal(name),
            maximum, "cxe_text", "cxe_document", nodes=nodes, depth=depth)
        result += f"""
            cxe_documents := cxe_documents || pg_catalog.jsonb_build_object({_literal(name)}, cxe_document);
            cxe_identities := cxe_identities || pg_catalog.jsonb_build_object({_literal(name)},
                {codecs._digest(namespace, domains[name], 'cxe_text')});
        """
    result += """
        IF pg_catalog.jsonb_typeof(cxe_packet->'originals'->'plan') IS DISTINCT FROM 'array'
        THEN RAISE EXCEPTION 'maintenance raw3 is not an array'; END IF;
        IF pg_catalog.jsonb_array_length(cxe_packet->'originals'->'plan') <> 3
        THEN RAISE EXCEPTION 'maintenance raw3 length differs'; END IF;
        cxe_original_frames := '[]'::jsonb;
    """
    for ordinal, (maximum, text_target, value_target, nodes, depth) in enumerate((
            (grants.FRAME_MAXIMA[0], "cxe_plan_json", "cxe_plan", plan.MAX_PARENT_NODES, plan.MAX_PARENT_DEPTH),
            (grants.FRAME_MAXIMA[1], "cxe_request_json", "cxe_request", WIRE_JSON_MAX_NODES, WIRE_JSON_MAX_DEPTH),
            (grants.FRAME_MAXIMA[2], "cxe_manifest_json", "cxe_manifest", packet.MAX_NODES, plan.MAX_PARENT_DEPTH))):
        result += _frame_sql(namespace, f"cxe_packet->'originals'->'plan'->{ordinal}", maximum,
            text_target, value_target, nodes=nodes, depth=depth)
        result += f"""
            cxe_original_frames := cxe_original_frames || pg_catalog.jsonb_build_array(
                pg_catalog.jsonb_build_object('position', {ordinal},
                    'bytesDigest', sxe_frame->'bytesDigest', 'byteCount', sxe_frame->'byteCount'));
        """
    return result


def _stream_sql(namespace):
    digests = tuple("cxe_stream->" + _literal(name) for name in sorted(HEADER_FIELDS) if name.endswith("Digest"))
    return f"""
        IF NOT {_closed('cxe_stream', HEADER_FIELDS)}
            OR cxe_stream->>'schema' IS DISTINCT FROM {_literal(stream.SCHEMA)}
            OR cxe_stream->>'sourceRevision' IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
            OR cxe_stream->>'operation' IS DISTINCT FROM {_literal(admission.OPERATION)}
            OR pg_catalog.jsonb_typeof(cxe_stream->'steps') IS DISTINCT FROM 'array'
        THEN RAISE EXCEPTION 'maintenance stream header shape differs'; END IF;
        {codecs._digests((*digests, "cxe_stream->'operationId'"))}
        {codecs._integer("cxe_stream->'stepCount'", minimum=12, maximum=stream.MAX_STEPS)}
        {codecs._integer("cxe_stream->'totalBodyBytes'", minimum=24, maximum=stream.MAX_STEPS * stream.MAX_BODY_BYTES)}
        IF pg_catalog.jsonb_array_length(cxe_stream->'steps') <> (cxe_stream->>'stepCount')::integer
            OR cxe_packet->>'streamDigest' IS DISTINCT FROM
                {codecs._digest(namespace, stream.IDENTITY_DOMAIN, 'cxe_stream_json')}
        THEN RAISE EXCEPTION 'maintenance stream header identity or size differs'; END IF;
        cxe_bindings := pg_catalog.jsonb_build_object('planDigest', cxe_stream->'planDigest',
            'manifestDigest', cxe_stream->'manifestDigest', 'beforeVectorDigest', cxe_stream->'beforeVectorDigest');
        {codecs._wire(namespace, 'cxe_bindings', 'cxe_canonical', 1024, 16, 2)}
        cxe_chain := {codecs._digest(namespace, stream.SEED_DOMAIN, 'cxe_canonical')};
        cxe_phases := ARRAY[0, 1, 2, 4, 5, 6]::integer[];
        cxe_phase_position := 1; cxe_in_phase := FALSE; cxe_rows := 0; cxe_body_total := 0;
        FOR cxe_descriptor IN SELECT item.value FROM pg_catalog.jsonb_array_elements(cxe_stream->'steps')
            WITH ORDINALITY AS item(value, ordinal) ORDER BY item.ordinal
        LOOP
            {_live_sql()}
            IF NOT {_closed('cxe_descriptor', stream._DESCRIPTOR_FIELDS)}
                OR pg_catalog.jsonb_typeof(cxe_descriptor->'kind') IS DISTINCT FROM 'string'
                OR cxe_descriptor->>'kind' NOT IN ('phase-before', 'row', 'phase-after')
            THEN RAISE EXCEPTION 'maintenance stream descriptor shape differs'; END IF;
            {codecs._integer("cxe_descriptor->'phaseOrdinal'", maximum=6)}
            {codecs._integer("cxe_descriptor->'rowOrdinal'", maximum=255)}
            {codecs._integer("cxe_descriptor->'byteCount'", minimum=2, maximum=stream.MAX_BODY_BYTES)}
            {codecs._digests(("cxe_descriptor->'digest'",))}
            IF cxe_phase_position > 6 OR (cxe_descriptor->>'phaseOrdinal')::integer
                IS DISTINCT FROM cxe_phases[cxe_phase_position]
            THEN RAISE EXCEPTION 'maintenance stream phase order differs'; END IF;
            IF cxe_descriptor->>'kind' = 'phase-before' THEN
                IF cxe_in_phase OR (cxe_descriptor->>'rowOrdinal')::integer <> 0
                THEN RAISE EXCEPTION 'maintenance stream before edge differs'; END IF;
                cxe_in_phase := TRUE; cxe_rows := 0;
            ELSIF cxe_descriptor->>'kind' = 'row' THEN
                IF NOT cxe_in_phase OR cxe_rows >= 256
                    OR (cxe_descriptor->>'rowOrdinal')::integer <> cxe_rows
                THEN RAISE EXCEPTION 'maintenance stream row order differs'; END IF;
                cxe_rows := cxe_rows + 1;
            ELSE
                IF NOT cxe_in_phase OR (cxe_descriptor->>'rowOrdinal')::integer <> 0
                THEN RAISE EXCEPTION 'maintenance stream after edge differs'; END IF;
                cxe_in_phase := FALSE; cxe_phase_position := cxe_phase_position + 1;
            END IF;
            cxe_body_total := cxe_body_total + (cxe_descriptor->>'byteCount')::bigint;
            {codecs._wire(namespace, 'cxe_descriptor', 'cxe_canonical', 1024, 16, 2)}
            cxe_chain := {codecs._digest(namespace, stream.STEP_DOMAIN, 'cxe_chain, cxe_canonical')};
        END LOOP;
        IF cxe_phase_position <> 7 OR cxe_in_phase
            OR cxe_body_total IS DISTINCT FROM (cxe_stream->>'totalBodyBytes')::bigint
            OR cxe_chain IS DISTINCT FROM cxe_stream->>'chainDigest'
        THEN RAISE EXCEPTION 'maintenance stream final sequence or chain differs'; END IF;
    """


def _bindings_sql(namespace):
    controls = (
        ("currentRootEnrollment", authorization.ENROLLMENT_SCHEMA, authorization.ENROLLMENT_FIELDS,
            authorization.ENROLLMENT_PAYLOAD_SCHEMA, "cxe_enrollment"),
        ("grantEnrollment", grants.ENROLLMENT_SCHEMA, grants.ENROLLMENT_FIELDS,
            grants.ENROLLMENT_PAYLOAD_SCHEMA, "cxe_grant_enrollment"),
        ("grant", grants.GRANT_SCHEMA, grants.GRANT_FIELDS, grants.GRANT_PAYLOAD_SCHEMA, "cxe_grant"),
        ("reserveRequest", authorization.REQUEST_SCHEMA, authorization.RESERVE_FIELDS,
            authorization.REQUEST_PAYLOAD_SCHEMA, "cxe_reserve"),
        ("reserveReceipt", authorization.RECEIPT_SCHEMA, authorization.RECEIPT_FIELDS,
            authorization.RECEIPT_PAYLOAD_SCHEMA, "cxe_receipt"),
    )
    result = ""
    for name, schema, fields, payload_schema, target in controls:
        expression = "cxe_documents->" + _literal(name)
        result += codecs._signed_shape(expression, schema, fields, payload_schema)
        result += f"{target} := {expression}->'payload';\n"
    result += codecs._signed_shape("cxe_plan", plan.ENVELOPE_SCHEMA, plan.PAYLOAD_FIELDS, plan.SCHEMA)
    result += f"""
        cxe_parent := cxe_plan->'payload'; cxe_snapshot := cxe_documents->'computationSnapshot';
        IF NOT {_closed('cxe_snapshot', admission.pending.computation._SNAPSHOT_FIELDS)}
            OR cxe_snapshot->>'schema' IS DISTINCT FROM {_literal(admission.pending.computation.SNAPSHOT_SCHEMA)}
            OR cxe_snapshot->>'sourceRevision' IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
            OR cxe_snapshot->'signedSnapshotDigest' IS DISTINCT FROM 'null'::jsonb
            OR cxe_snapshot->'signedCapabilityId' IS DISTINCT FROM 'null'::jsonb
            OR NOT {_closed('cxe_request', plan.requests.shape.TYPED_REQUEST_FIELDS)}
            OR cxe_request->>'schema' IS DISTINCT FROM {_literal(plan.requests.shape.TYPED_REQUEST_SCHEMA)}
            OR cxe_request->>'handler' IS DISTINCT FROM {_literal(authority.operation_spec(admission.OPERATION)['handler'])}
            OR cxe_request->>'operationManifestDigest' IS DISTINCT FROM {_literal(authority.OPERATION_MANIFEST_DIGEST)}
            OR NOT {_closed('cxe_manifest', ('schema', 'context', 'schedule', 'groups'))}
            OR cxe_manifest->>'schema' IS DISTINCT FROM {_literal(plan.manifests.SCHEMA)}
            OR NOT {_closed("cxe_manifest->'context'", plan.manifests.CONTEXT_FIELDS)}
            OR cxe_grant_enrollment->'operations' IS DISTINCT FROM '["{admission.OPERATION}"]'::jsonb
        THEN RAISE EXCEPTION 'maintenance original source shapes differ'; END IF;
    """
    pairs = []
    for document in ("cxe_grant", "cxe_parent", "cxe_snapshot", "cxe_reserve", "cxe_request", "cxe_manifest->'context'"):
        pairs += [(f"{document}->{_literal(name)}", f"cxe_stream->{_literal(name)}")
            for name in ("operation", "operationId", "requestDigest")]
    pairs += [(f"{document}->'configurationDigest'", "cxe_stream->'configurationDigest'")
        for document in ("cxe_grant", "cxe_parent", "cxe_manifest->'context'")]
    for document in ("cxe_grant", "cxe_parent", "cxe_reserve", "cxe_receipt"):
        pairs += [(f"{document}->{_literal(name)}", f"cxe_packet->{_literal(name)}")
            for name in ("issuedAtEpochNs", "expiresAtEpochNs")]
    pairs += [("cxe_snapshot->'originalIssuedAtEpochNs'", "cxe_packet->'issuedAtEpochNs'"),
        ("cxe_snapshot->'originalExpiresAtEpochNs'", "cxe_packet->'expiresAtEpochNs'"),
        ("cxe_parent->'manifestDigest'", "cxe_stream->'manifestDigest'"),
        ("cxe_parent->'requestByteCount'", "cxe_packet->'originals'->'plan'->1->'byteCount'"),
        ("cxe_parent->'manifestByteCount'", "cxe_packet->'originals'->'plan'->2->'byteCount'"),
        ("cxe_parent->>'requestBytesDigest'", codecs._digest(namespace, plan.REQUEST_DOMAIN, 'cxe_request_json')),
        ("cxe_stream->>'planDigest'", codecs._digest(namespace, plan.IDENTITY_DOMAIN, 'cxe_plan_json')),
        ("cxe_stream->>'manifestDigest'", codecs._digest(namespace, plan.MANIFEST_DOMAIN, 'cxe_manifest_json')),
        ("cxe_snapshot->>'retainedRecordDigest'", codecs._digest(namespace,
            admission.computation.ORIGINAL_RECORD_DOMAIN, 'cxe_plan_json, cxe_request_json, cxe_manifest_json')),
        ("cxe_grant->'originalFrames'", "cxe_original_frames"),
        ("cxe_snapshot->'originalFrames'", "cxe_original_frames"),
        ("cxe_grant->'requestAuthorizationDigest'", "cxe_packet->'authorizationDigest'"),
        ("cxe_grant->'manifestDigest'", "cxe_stream->'manifestDigest'"),
        ("cxe_packet->'grantDigest'", "cxe_identities->'grant'"),
        ("cxe_packet->'pendingDecisionDigest'", "cxe_identities->'reserveReceipt'"),
        ("cxe_grant->'grantEnrollmentDigest'", "cxe_identities->'grantEnrollment'"),
        ("cxe_grant_enrollment->'currentRootEnrollmentDigest'", "cxe_identities->'currentRootEnrollment'"),
        ("cxe_reserve->>'action'", "'reserve'"), ("cxe_receipt->>'action'", "'reserve'"),
        ("cxe_reserve->'beforeVector'", "cxe_before"), ("cxe_reserve->'afterVector'", "cxe_after"),
        ("cxe_reserve->'capabilityDigest'", "cxe_identities->'grant'"),
        ("cxe_snapshot->'capabilityDigest'", "cxe_identities->'grant'"),
        ("cxe_reserve->'snapshotDigest'", "cxe_identities->'computationSnapshot'"),
        ("cxe_receipt->'requestDigest'", "cxe_identities->'reserveRequest'"),
        ("cxe_receipt->'pendingRequestDigest'", "cxe_identities->'reserveRequest'"),
        ("cxe_receipt->'previousHeadDigest'", "cxe_reserve->'predecessorHeadDigest'"),
        ("cxe_receipt->'fence'", "cxe_reserve->'fence'"),
        ("cxe_manifest->'context'->'sourceRevision'", "cxe_packet->'sourceRevision'"),
        ("cxe_snapshot->'producerMeasurementDigest'", "cxe_enrollment->'computation'->'measurementDigest'"),
        ("cxe_reserve->'producerMeasurementDigest'", "cxe_enrollment->'computation'->'measurementDigest'"),
        ("cxe_receipt->'producerMeasurementDigest'", "cxe_enrollment->'state'->'measurementDigest'"),
        ("cxe_grant->'authorizerMeasurementDigest'", "cxe_grant_enrollment->'authorizer'->'measurementDigest'")]
    for document in ("cxe_grant", "cxe_grant_enrollment", "cxe_snapshot", "cxe_reserve", "cxe_receipt"):
        pairs += [(f"{document}->{_literal(name)}", f"cxe_enrollment->{_literal(name)}")
            for name in ("databaseId", "generationDigest")]
    for document, name in (("cxe_grant", "currentRootEnrollmentDigest"), ("cxe_snapshot", "enrollmentDigest"),
            ("cxe_reserve", "enrollmentDigest"), ("cxe_receipt", "enrollmentDigest")):
        pairs.append((f"{document}->{_literal(name)}", "cxe_identities->'currentRootEnrollment'"))
    for name in ("planDigest", "beforeVectorDigest", "afterVectorDigest", "resultDigest"):
        pairs += [(f"{document}->{_literal(name)}", f"cxe_stream->{_literal(name)}")
            for document in ("cxe_grant", "cxe_snapshot")]
    for name in ("beforeVectorDigest", "afterVectorDigest"):
        pairs.append((f"cxe_receipt->{_literal(name)}", f"cxe_stream->{_literal(name)}"))
    marker = {
        "pending_decision_digest": "cxe_identities->'reserveReceipt'",
        "source_revision": "cxe_packet->'sourceRevision'", "database_id": "cxe_enrollment->'databaseId'",
        "enrollment_digest": "cxe_identities->'currentRootEnrollment'", "generation_digest": "cxe_enrollment->'generationDigest'",
        "pending_request_digest": "cxe_identities->'reserveRequest'", "pending_sequence": "cxe_receipt->'sequence'",
        "predecessor_sequence": "cxe_reserve->'predecessorSequence'", "predecessor_head_digest": "cxe_reserve->'predecessorHeadDigest'",
        "fence": "cxe_reserve->'fence'", "operation": "cxe_stream->'operation'",
        "request_digest": "cxe_stream->'requestDigest'", "operation_id": "cxe_stream->'operationId'",
        "capability_digest": "cxe_identities->'grant'", "snapshot_digest": "cxe_identities->'computationSnapshot'",
        "before_vector_digest": "cxe_stream->'beforeVectorDigest'", "after_vector_digest": "cxe_stream->'afterVectorDigest'",
        "result_digest": "cxe_stream->'resultDigest'",
    }
    if tuple(marker) != authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS:
        raise ValueError("maintenance packet marker source inventory changed")
    pairs += [("cxe_marker->" + _literal(name), value) for name, value in marker.items()]
    result += codecs._equal(pairs, "maintenance packet original scope or marker differs")
    result += f"""
        {codecs._integer("cxe_enrollment->'maxRecords'", minimum=2, maximum=authorization.MAX_RECORDS)}
        {codecs._integer("cxe_enrollment->'maxControlAgeNs'", minimum=1, maximum=authority.VERIFIER_RESPONSE_MAX_AGE_NS)}
        {codecs._integer("cxe_enrollment->'maxClockSkewNs'", maximum=authority.VERIFIER_MAX_CLOCK_SKEW_NS)}
        {codecs._integer("cxe_grant_enrollment->'maximumGrantAgeNs'", minimum=1, maximum=authority.VERIFIER_RESPONSE_MAX_AGE_NS)}
        {codecs._integer("cxe_grant_enrollment->'maximumClockSkewNs'", maximum=authority.VERIFIER_MAX_CLOCK_SKEW_NS)}
        IF cxe_expires - cxe_issued > (cxe_enrollment->>'maxControlAgeNs')::bigint
            OR cxe_expires - cxe_issued > (cxe_grant_enrollment->>'maximumGrantAgeNs')::bigint
            OR cxe_issued::numeric > pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000000)
                + LEAST((cxe_enrollment->>'maxClockSkewNs')::bigint,
                    (cxe_grant_enrollment->>'maximumClockSkewNs')::bigint)
            OR (cxe_marker->>'pending_sequence')::bigint >= (cxe_enrollment->>'maxRecords')::bigint
            OR (cxe_marker->>'pending_sequence')::bigint <> (cxe_marker->>'predecessor_sequence')::bigint + 1
        THEN RAISE EXCEPTION 'maintenance packet original interval or sequence differs'; END IF;
    """
    return result


def packet_body_sql(namespace: str) -> str:
    """Render consistency only; the owning protected function supplies trust."""
    namespace = primary_tree_sql._namespace(namespace)
    if (packet.MAX_BYTES != 8 * 1024 * 1024 or stream.PHASES != (0, 1, 2, 4, 5, 6)
            or stream.MAX_STEPS != 1548 or admission.OPERATION != "webauthn.challenge.maintain"
            or tuple(name for name, _maximum in packet.CONTROL_MAXIMA) != (
                "currentRootEnrollment", "grantEnrollment", "grant", "reserveRequest", "reserveReceipt", "computationSnapshot")):
        raise ValueError("maintenance packet source inventory changed")
    frames = _frame_sql(namespace, "cxe_packet->'streamHeader'", stream.MAX_HEADER_BYTES,
        "cxe_stream_json", "cxe_stream", nodes=stream.MAX_HEADER_NODES, depth=packet.MAX_DEPTH)
    for name, text, target in (("beforeVector", "cxe_before_vector_json", "cxe_before"),
            ("afterVector", "cxe_after_vector_json", "cxe_after")):
        frames += _frame_sql(namespace, "cxe_packet->" + _literal(name), vector.MAX_BYTES,
            text, target, nodes=vector.MAX_NODES, depth=vector.MAX_DEPTH)
        frames += f"""
            IF NOT {_closed(target, vector._FIELDS)}
                OR {target}->>'schema' IS DISTINCT FROM {_literal(vector.SCHEMA)}
                OR {target}->'schemaVersion' IS DISTINCT FROM '{authority.SCHEMA_VERSION}'::jsonb
                OR {target}->>'sourceRevision' IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
                OR pg_catalog.jsonb_typeof({target}->'primaryRoots') IS DISTINCT FROM 'array'
                OR pg_catalog.jsonb_typeof({target}->'countedRoots') IS DISTINCT FROM 'array'
            THEN RAISE EXCEPTION 'maintenance complete vector envelope differs'; END IF;
            {codecs._digests(tuple(target + '->' + _literal(field) for field in vector._DIGEST_FIELDS))}
        """
    return f"""
        DECLARE
            sxe_measured record; sxe_rendered record; sxe_frame jsonb;
            sxe_maximum bigint; sxe_count bigint; sxe_total bigint := 0;
            sxe_raw bytea; sxe_signature bytea;
            cxe_canonical text; cxe_text text; cxe_document jsonb;
            cxe_documents jsonb; cxe_identities jsonb; cxe_original_frames jsonb;
            cxe_plan_json text; cxe_request_json text; cxe_manifest_json text;
            cxe_plan jsonb; cxe_request jsonb; cxe_manifest jsonb; cxe_parent jsonb;
            cxe_enrollment jsonb; cxe_grant_enrollment jsonb; cxe_grant jsonb;
            cxe_reserve jsonb; cxe_receipt jsonb; cxe_snapshot jsonb;
            cxe_before jsonb; cxe_after jsonb; cxe_bindings jsonb; cxe_descriptor jsonb;
            cxe_phases integer[]; cxe_phase_position integer; cxe_rows integer;
            cxe_in_phase boolean; cxe_body_total bigint; cxe_chain text;
        BEGIN
            {_live_sql()}
            IF cxe_packet_json IS NULL OR pg_catalog.octet_length(cxe_packet_json) NOT BETWEEN 2 AND {packet.MAX_BYTES}
                OR pg_catalog.length(cxe_packet_json) IS DISTINCT FROM pg_catalog.octet_length(cxe_packet_json)
                OR cxe_packet_digest IS NULL OR cxe_packet_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
                OR cxe_pending_decision_digest IS NULL
                OR cxe_pending_decision_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
            THEN RAISE EXCEPTION 'maintenance packet original framing differs'; END IF;
            cxe_packet := cxe_packet_json::jsonb;
            IF NOT {_closed('cxe_packet', packet.FIELDS)}
                OR cxe_packet->>'schema' IS DISTINCT FROM {_literal(packet.SCHEMA)}
                OR cxe_packet->>'sourceRevision' IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
                OR cxe_packet->>'operation' IS DISTINCT FROM {_literal(admission.OPERATION)}
            THEN RAISE EXCEPTION 'maintenance packet source shape differs'; END IF;
            {codecs._wire(namespace, 'cxe_packet', 'cxe_canonical', packet.MAX_BYTES, packet.MAX_NODES, packet.MAX_DEPTH)}
            IF cxe_canonical COLLATE "C" IS DISTINCT FROM cxe_packet_json COLLATE "C"
                OR cxe_packet_digest IS DISTINCT FROM {codecs._digest(namespace, packet.IDENTITY_DOMAIN, 'cxe_packet_json')}
                OR cxe_packet->>'pendingDecisionDigest' IS DISTINCT FROM cxe_pending_decision_digest
            THEN RAISE EXCEPTION 'maintenance packet identity differs'; END IF;
            {codecs._digests(tuple("cxe_packet->" + _literal(field) for field in ('authorizationDigest', 'grantDigest', 'pendingDecisionDigest', 'streamDigest')))}
            {codecs._integer("cxe_packet->'issuedAtEpochNs'", minimum=1)}
            {codecs._integer("cxe_packet->'expiresAtEpochNs'", minimum=1)}
            cxe_issued := (cxe_packet->>'issuedAtEpochNs')::bigint;
            cxe_expires := (cxe_packet->>'expiresAtEpochNs')::bigint;
            IF cxe_expires <= cxe_issued THEN RAISE EXCEPTION 'maintenance packet original interval is empty'; END IF;
            cxe_deadline_epoch_ns := LEAST(cxe_deadline_epoch_ns, cxe_expires);
            {_live_sql()}
            {frames}
            {_stream_sql(namespace)}
            cxe_marker := cxe_packet->'marker';
            IF NOT {_closed('cxe_marker', authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS)}
                OR pg_catalog.jsonb_typeof(cxe_marker->'database_id') IS DISTINCT FROM 'string'
                OR cxe_marker->>'database_id' COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{{0,127}}$'
            THEN RAISE EXCEPTION 'maintenance packet marker shape differs'; END IF;
            {codecs._digests(tuple("cxe_marker->" + _literal(name) for name in authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS if name.endswith('_digest')) + ("cxe_marker->'operation_id'",))}
            {codecs._integer("cxe_marker->'pending_sequence'", minimum=1, maximum=authorization.MAX_RECORDS - 1)}
            {codecs._integer("cxe_marker->'predecessor_sequence'", maximum=authorization.MAX_RECORDS - 2)}
            {codecs._integer("cxe_marker->'fence'", minimum=1)}
            {codecs._wire(namespace, "cxe_packet->'result'", 'cxe_result_json', 16384, 2048, 12)}
            IF cxe_stream->>'beforeVectorDigest' IS DISTINCT FROM {codecs._digest(namespace, vector.IDENTITY_DOMAIN, 'cxe_before_vector_json')}
                OR cxe_stream->>'afterVectorDigest' IS DISTINCT FROM {codecs._digest(namespace, vector.IDENTITY_DOMAIN, 'cxe_after_vector_json')}
                OR cxe_stream->>'resultDigest' IS DISTINCT FROM {codecs._digest(namespace, stream.RESULT_DOMAIN, 'cxe_result_json')}
                OR cxe_stream->>'operationId' IS DISTINCT FROM {codecs._digest(namespace, 'catchplate.policyAuthorityOperation/v2', "cxe_stream->>'operation', cxe_stream->>'requestDigest'")}
            THEN RAISE EXCEPTION 'maintenance stream vector/result/operation joins differ'; END IF;
            {_originals_sql(namespace)}
            {_bindings_sql(namespace)}
            {_live_sql()}
        END;
    """
