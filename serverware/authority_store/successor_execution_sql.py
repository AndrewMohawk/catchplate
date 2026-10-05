"""Fixed protected successor custody issuance and identifier-only execution.

SQL does not verify Ed25519 or replay proofs. The separately pinned issuer is
an explicit trusted boundary: its fixed Python owner must run genuine original
grant/pending/plan admission, never accept a candidate as authority, and retain
the exact derived packet. Only that issuer may store packets; only the distinct
executor may consume protected custody by pending decision and packet digest.
The third, separately pinned recovery role can read exact historical originals
by both independently held identifiers in a read-only transaction. Its SQL
does not renew controls, verify signatures or turn expired packets into grants.

The actual protected Python owner compares the complete source-generated schema
manifest (including function and all trigger bodies/modes) on the SAME admitted
SERIALIZABLE connection before the fixed call and after it, before commit.
The expected manifest digest is independently admitted, not learned from that
connection. This renderer invents no SQL catalog assertion or success flag.
The schema owner is higher-trust NOLOGIN; lower roles have no DDL/direct DML.
That boundary is not protection against a malicious schema owner or host.

No installer or grants occur here. Existing v3/revocation gates, planner rows,
writer tokens and GUCs are untouched. Actual source CAS/maintained full roots
and the unique immutable marker are one outer transaction. The marker is a
database-domain one-use witness, not an external anti-rollback oracle. Any
failure aborts the owning transaction; no retry, reset or internal commit is
provided. A returned marker is transaction-local, not postcommit assurance.

Packet byte limits precede JSON parsing; bounded ASCII walks/transport checks
also cover canonicality and original commitments. PostgreSQL parse/detoast and
driver allocations are not Python work accounting or process-memory bounds.
Inherited positive waits are not reset; the effective deadline is the minimum
of original packet expiry and this statement's original start plus timeout.
"""
from __future__ import annotations

import re
import textwrap

from serverware import authority_contract as authority
from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_computation as computation
from serverware import authority_current_root_plan_replay as replay
from serverware import authority_current_root_vector as vector
from serverware import authority_successor_execution_grant as grants
from serverware import authority_successor_execution_packet as packet
from serverware import authority_oidc_session_activation_delivery_execution_packet as delivery_packet
from serverware.authority_store import current_root_execution_sql as effects
from serverware.authority_store.mutation_sql import _schema_name
from serverware.authority_store.revocation_retained_sql import _closed, _literal


ISSUE_FUNCTION = "serverware_policy_authority_issue_successor_execution"
EXECUTE_FUNCTION = "serverware_policy_authority_execute_successor"
READ_FUNCTION = "serverware_policy_authority_read_successor_execution"
ISSUER_IDENTITY_DOMAIN = "serverware.policyAuthoritySuccessorIssuerSession/v1"
EXECUTOR_IDENTITY_DOMAIN = "serverware.policyAuthoritySuccessorExecutorSession/v1"
RECOVERY_IDENTITY_DOMAIN = "serverware.policyAuthoritySuccessorRecoverySession/v1"
_COLUMNS = ("pending_decision_digest", "packet_digest", "packet_json", "enrollment_digest",
    "generation_digest", "capability_digest", "operation_id", "fence", "issued_at_epoch_ns",
    "expires_at_epoch_ns", "issuer_identity_digest")
_FRAME_FIELDS = ("base64Url", "bytesDigest", "byteCount")
_SELECTED_FIELDS = ("table", "key", "keyDigest", "present", "row", "contractSelector")
_MUTATION_FIELDS = ("templateId", "operation", "table", "key", "keyDigest", "expectedRow", "row")


def _digest(namespace, domain, expression):
    return f"{namespace}.serverware_policy_authority_domain_digest({_literal(domain)}, {expression})"


def _wire(namespace, expression, output, maximum, nodes=packet.MAX_NODES, depth=packet.MAX_DEPTH):
    return f"""
        SELECT * INTO STRICT sxe_measured FROM {namespace}.serverware_policy_authority_wire_walk(
            {expression}, {depth}, {nodes}, {maximum}, FALSE);
        SELECT * INTO STRICT sxe_rendered FROM {namespace}.serverware_policy_authority_wire_walk(
            {expression}, {depth}, sxe_measured.visited_nodes, sxe_measured.emitted_bytes, TRUE);
        IF sxe_rendered.visited_nodes IS DISTINCT FROM sxe_measured.visited_nodes
            OR sxe_rendered.emitted_bytes IS DISTINCT FROM sxe_measured.emitted_bytes
            OR pg_catalog.octet_length(sxe_rendered.rendered) IS DISTINCT FROM sxe_measured.emitted_bytes
        THEN RAISE EXCEPTION 'successor custody canonical measurement changed'; END IF;
        {output} := sxe_rendered.rendered;
    """


def _integer(expression, *, minimum=0, maximum=2**63 - 1):
    return f"""
        IF pg_catalog.jsonb_typeof({expression}) IS DISTINCT FROM 'number'
            OR ({expression} #>> '{{}}') COLLATE "C" !~ '^(0|[1-9][0-9]{{0,18}})$'
        THEN RAISE EXCEPTION 'successor custody integer type is invalid'; END IF;
        IF ({expression} #>> '{{}}')::numeric NOT BETWEEN {minimum} AND {maximum}
        THEN RAISE EXCEPTION 'successor custody integer is out of bounds'; END IF;
    """


def _digests(expressions):
    return "\n".join(f"""
        IF pg_catalog.jsonb_typeof({value}) IS DISTINCT FROM 'string'
            OR ({value} #>> '{{}}') COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
        THEN RAISE EXCEPTION 'successor custody digest is not canonical'; END IF;
    """ for value in expressions)


def _equal(pairs, label):
    return ("IF " + " OR ".join(f"({left}) IS DISTINCT FROM ({right})" for left, right in pairs)
        + " THEN RAISE EXCEPTION " + _literal(label) + "; END IF;\n")


def _live():
    return """
        IF sxe_deadline IS NULL OR sxe_deadline <= 0
            OR pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000000) >= sxe_deadline
        THEN RAISE EXCEPTION 'successor custody original statement or packet deadline expired'; END IF;
    """


def _frame():
    """Decode one bounded exact raw frame; selected maxima are source-only."""
    return f"""
        IF NOT {_closed('sxe_frame', _FRAME_FIELDS)}
        THEN RAISE EXCEPTION 'successor original frame is not exact'; END IF;
        {_integer("sxe_frame->'byteCount'", minimum=2)}
        sxe_count := (sxe_frame->>'byteCount')::bigint;
        IF sxe_count > sxe_maximum
            OR pg_catalog.jsonb_typeof(sxe_frame->'base64Url') IS DISTINCT FROM 'string'
            OR pg_catalog.length(sxe_frame->>'base64Url')::bigint <> (4 * sxe_count + 2) / 3
            OR (sxe_frame->>'base64Url') COLLATE "C" !~ '^[A-Za-z0-9_-]+$'
        THEN RAISE EXCEPTION 'successor original frame exceeds its exact transport bound'; END IF;
        {_digests(("sxe_frame->'bytesDigest'",))}
        sxe_raw := pg_catalog.decode(pg_catalog.translate(sxe_frame->>'base64Url', '-_', '+/')
            || pg_catalog.repeat('=', (4 - pg_catalog.length(sxe_frame->>'base64Url') % 4) % 4), 'base64');
        IF pg_catalog.octet_length(sxe_raw) IS DISTINCT FROM sxe_count
            OR 'sha256:' || pg_catalog.encode(pg_catalog.sha256(sxe_raw), 'hex')
                IS DISTINCT FROM sxe_frame->>'bytesDigest'
            OR pg_catalog.translate(pg_catalog.encode(sxe_raw, 'base64'), E'+/=\\n\\r', '-_')
                IS DISTINCT FROM sxe_frame->>'base64Url'
        THEN RAISE EXCEPTION 'successor original frame bytes changed'; END IF;
        sxe_total := sxe_total + sxe_count;
        IF sxe_total > {packet.MAX_BYTES}
        THEN RAISE EXCEPTION 'successor original aggregate exceeds source ceiling'; END IF;
    """


def _signed_shape(expression, schema, fields, payload_schema):
    return f"""
        IF NOT {_closed(expression, ('schema', 'payload', 'signatureBase64Url'))}
            OR {expression}->>'schema' IS DISTINCT FROM {_literal(schema)}
            OR NOT {_closed(expression + "->'payload'", fields)}
            OR {expression}->'payload'->>'schema' IS DISTINCT FROM {_literal(payload_schema)}
            OR {expression}->'payload'->>'sourceRevision' IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
            OR pg_catalog.jsonb_typeof({expression}->'signatureBase64Url') IS DISTINCT FROM 'string'
            OR ({expression}->>'signatureBase64Url') COLLATE "C" !~ '^[A-Za-z0-9_-]{{86}}$'
        THEN RAISE EXCEPTION 'successor original signed control shape changed'; END IF;
        sxe_signature := pg_catalog.decode(pg_catalog.translate({expression}->>'signatureBase64Url', '-_', '+/') || '==', 'base64');
        IF pg_catalog.octet_length(sxe_signature) <> 64
            OR pg_catalog.translate(pg_catalog.encode(sxe_signature, 'base64'), E'+/=\\n\\r', '-_')
                IS DISTINCT FROM {expression}->>'signatureBase64Url'
        THEN RAISE EXCEPTION 'successor original signature transport is not canonical'; END IF;
    """


def _originals(namespace, *, delivery=False):
    if type(delivery) is not bool:
        raise ValueError("successor original profile must be source fixed")
    grant_wire = delivery_packet.grants if delivery else grants
    grant_enrollment = delivery_packet.enrollments if delivery else grants
    snapshot = delivery_packet.computation if delivery else computation
    inventory = delivery_packet.CONTROL_MAXIMA if delivery else packet._CONTROL_MAXIMA
    original_fields = delivery_packet.ORIGINAL_FIELDS if delivery else packet.ORIGINAL_FIELDS
    controls = {name: {"maximum": maximum, "nodes": authorization.MAX_NODES,
        "depth": authorization.MAX_DEPTH} for name, maximum in inventory}
    controls["grantEnrollment"].update(nodes=grant_enrollment.MAX_NODES, depth=grant_enrollment.MAX_DEPTH)
    controls["grant"].update(nodes=grant_wire.MAX_NODES, depth=grant_wire.MAX_DEPTH)
    controls["computationSnapshot"].update(nodes=snapshot.MAX_SNAPSHOT_NODES, depth=4)
    domains = {"currentRootEnrollment": authorization.ENROLLMENT_IDENTITY_DOMAIN,
        "grantEnrollment": grant_enrollment.ENROLLMENT_IDENTITY_DOMAIN, "grant": grant_wire.GRANT_IDENTITY_DOMAIN,
        "reserveRequest": authorization.REQUEST_IDENTITY_DOMAIN,
        "reserveReceipt": authorization.RECEIPT_IDENTITY_DOMAIN,
        "computationSnapshot": snapshot.SNAPSHOT_DOMAIN}
    if delivery:
        for name in ("callerEnrollment", "callerAuthorization"):
            controls[name].update(nodes=delivery_packet.caller.MAX_NODES, depth=delivery_packet.caller.MAX_DEPTH)
        domains.update(callerEnrollment=delivery_packet.caller.ENROLLMENT_IDENTITY_DOMAIN,
            callerAuthorization=delivery_packet.caller.REQUEST_IDENTITY_DOMAIN)
        maxima = {delivery_packet.OPERATION: list(grant_wire.FRAME_MAXIMA)}
    else:
        maxima = {operation: list(replay._frame_maxima(operation))
            for operation in sorted(replay.OPERATIONS)}
    # Only the explicit fixed consume branch uses its dedicated raw2 grammar.
    # Encrypted frames remain opaque bytes: no key, decrypt or JSON fallback.
    cases = "\n".join(f"WHEN {_literal(name)} THEN {_literal(domain)}" for name, domain in domains.items())
    return f"""
        IF NOT {_closed("sxe_packet->'originals'", original_fields)}
        THEN RAISE EXCEPTION 'successor original inventory is not exact'; END IF;
        sxe_documents := '{{}}'::jsonb; sxe_identities := '{{}}'::jsonb; sxe_total := 0;
        FOR sxe_name, sxe_control IN SELECT item.key, item.value
            FROM pg_catalog.jsonb_each({_literal(effects._json(controls))}::jsonb) AS item
            ORDER BY item.key COLLATE "C"
        LOOP
            sxe_maximum := (sxe_control->>'maximum')::bigint;
            sxe_frame := sxe_packet->'originals'->sxe_name;
            {_frame()}
            sxe_text := pg_catalog.convert_from(sxe_raw, 'UTF8');
            IF pg_catalog.length(sxe_text) IS DISTINCT FROM pg_catalog.octet_length(sxe_text)
            THEN RAISE EXCEPTION 'successor original control must be canonical ASCII'; END IF;
            sxe_document := sxe_text::jsonb;
            {_wire(namespace, 'sxe_document', 'sxe_canonical', 'sxe_maximum',
                "(sxe_control->>'nodes')::bigint", "(sxe_control->>'depth')::integer")}
            IF sxe_canonical IS DISTINCT FROM sxe_text
            THEN RAISE EXCEPTION 'successor original control is not canonical'; END IF;
            sxe_domain := CASE sxe_name {cases} ELSE NULL END;
            sxe_documents := sxe_documents || pg_catalog.jsonb_build_object(sxe_name, sxe_document);
            sxe_identities := sxe_identities || pg_catalog.jsonb_build_object(sxe_name,
                {namespace}.serverware_policy_authority_domain_digest(sxe_domain, sxe_text));
        END LOOP;
        sxe_plan_maxima := {_literal(effects._json(maxima))}::jsonb->crx_operation;
        IF pg_catalog.jsonb_typeof(sxe_packet->'originals'->'plan') IS DISTINCT FROM 'array'
        THEN RAISE EXCEPTION 'successor plan original inventory is not an array'; END IF;
        IF sxe_plan_maxima IS NULL OR pg_catalog.jsonb_array_length(sxe_packet->'originals'->'plan')
                IS DISTINCT FROM pg_catalog.jsonb_array_length(sxe_plan_maxima)
        THEN RAISE EXCEPTION 'successor plan original inventory differs from its family'; END IF;
        sxe_frames := '[]'::jsonb;
        FOR sxe_frame, sxe_position IN SELECT item.value, item.ordinal - 1
            FROM pg_catalog.jsonb_array_elements(sxe_packet->'originals'->'plan')
                WITH ORDINALITY AS item(value, ordinal) ORDER BY item.ordinal
        LOOP
            sxe_maximum := (sxe_plan_maxima->>sxe_position::integer)::bigint;
            {_frame()}
            sxe_frames := sxe_frames || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
                'position', sxe_position, 'bytesDigest', sxe_frame->'bytesDigest', 'byteCount', sxe_frame->'byteCount'));
        END LOOP;
    """


def _bindings(namespace, *, delivery=False):
    if type(delivery) is not bool:
        raise ValueError("successor binding profile must be source fixed")
    grant_wire = delivery_packet.grants if delivery else grants
    grant_enrollment = delivery_packet.enrollments if delivery else grants
    snapshot = delivery_packet.computation if delivery else computation
    snapshot_fields = snapshot._FIELDS if delivery else snapshot._SNAPSHOT_FIELDS
    shared = ("databaseId", "generationDigest", "operation", "requestDigest", "operationId")
    snapshot_joins = ("sourceRevision", "databaseId", "generationDigest", "operation", "requestDigest",
        "operationId", "retainedRecordDigest", "planDigest", "beforeVectorDigest", "afterVectorDigest",
        "resultDigest", "originalFrames", "originalIssuedAtEpochNs", "originalExpiresAtEpochNs",
        "signedSnapshotDigest", "signedCapabilityId")
    if delivery:
        snapshot_joins = snapshot_joins[:-2]
    pairs = [("sxe_grant->" + _literal(name), "sxe_snapshot->" + _literal(name)) for name in snapshot_joins]
    pairs += [("sxe_reserve->" + _literal(name), "sxe_snapshot->" + _literal(name)) for name in shared]
    pairs += [("sxe_receipt->" + _literal(name), "sxe_reserve->" + _literal(name))
        for name in ("enrollmentDigest", "databaseId", "generationDigest", "fence", "issuedAtEpochNs", "expiresAtEpochNs")]
    pairs += [("sxe_packet->" + _literal(name), "sxe_reserve->" + _literal(name))
        for name in ("operation", "requestDigest", "operationId", "issuedAtEpochNs", "expiresAtEpochNs")]
    pairs += [("sxe_reserve->'beforeVector'", "sxe_packet->'beforeVector'"),
        ("sxe_reserve->'afterVector'", "sxe_packet->'afterVector'"),
        ("sxe_reserve->>'action'", "'reserve'"), ("sxe_receipt->>'action'", "'reserve'"),
        ("sxe_snapshot->'originalFrames'", "sxe_frames"), ("sxe_grant->'requestAuthorizationDigest'", "sxe_packet->'authorizationDigest'"),
        ("sxe_grant->'grantEnrollmentDigest'", "sxe_identities->'grantEnrollment'"),
        ("sxe_grant_enrollment->'currentRootEnrollmentDigest'", "sxe_identities->'currentRootEnrollment'"),
        ("sxe_grant->'currentRootEnrollmentDigest'", "sxe_identities->'currentRootEnrollment'"),
        ("sxe_snapshot->'enrollmentDigest'", "sxe_identities->'currentRootEnrollment'"),
        ("sxe_reserve->'enrollmentDigest'", "sxe_identities->'currentRootEnrollment'"),
        ("sxe_snapshot->'databaseId'", "sxe_enrollment->'databaseId'"),
        ("sxe_snapshot->'generationDigest'", "sxe_enrollment->'generationDigest'"),
        ("sxe_grant_enrollment->'databaseId'", "sxe_enrollment->'databaseId'"),
        ("sxe_grant_enrollment->'generationDigest'", "sxe_enrollment->'generationDigest'"),
        ("sxe_snapshot->'producerMeasurementDigest'", "sxe_enrollment->'computation'->'measurementDigest'"),
        ("sxe_reserve->'producerMeasurementDigest'", "sxe_enrollment->'computation'->'measurementDigest'"),
        ("sxe_receipt->'producerMeasurementDigest'", "sxe_enrollment->'state'->'measurementDigest'"),
        ("sxe_grant->'authorizerMeasurementDigest'", "sxe_grant_enrollment->'authorizer'->'measurementDigest'"),
        ("sxe_reserve->'capabilityDigest'", "sxe_identities->'grant'"),
        ("sxe_snapshot->'capabilityDigest'", "sxe_identities->'grant'"),
        ("sxe_reserve->'snapshotDigest'", "sxe_identities->'computationSnapshot'"),
        ("sxe_receipt->'requestDigest'", "sxe_identities->'reserveRequest'"),
        ("sxe_receipt->'pendingRequestDigest'", "sxe_identities->'reserveRequest'"),
        ("sxe_receipt->'previousHeadDigest'", "sxe_reserve->'predecessorHeadDigest'"),
        ("sxe_grant->'issuedAtEpochNs'", "sxe_packet->'issuedAtEpochNs'")]
    marker = {"pending_decision_digest": "sxe_identities->'reserveReceipt'",
        "enrollment_digest": "sxe_identities->'currentRootEnrollment'",
        "database_id": "sxe_enrollment->'databaseId'", "generation_digest": "sxe_enrollment->'generationDigest'",
        "pending_request_digest": "sxe_identities->'reserveRequest'", "pending_sequence": "sxe_receipt->'sequence'",
        "predecessor_sequence": "sxe_reserve->'predecessorSequence'",
        "predecessor_head_digest": "sxe_reserve->'predecessorHeadDigest'", "fence": "sxe_reserve->'fence'",
        "operation": "sxe_packet->'operation'", "request_digest": "sxe_packet->'requestDigest'",
        "operation_id": "sxe_packet->'operationId'", "capability_digest": "sxe_identities->'grant'",
        "snapshot_digest": "sxe_identities->'computationSnapshot'", "before_vector_digest": "sxe_snapshot->'beforeVectorDigest'",
        "after_vector_digest": "sxe_snapshot->'afterVectorDigest'", "result_digest": "sxe_snapshot->'resultDigest'"}
    pairs += [("crx_marker->" + _literal(name), value) for name, value in marker.items()]
    for name in ("beforeVectorDigest", "afterVectorDigest"):
        pairs.append(("sxe_receipt->" + _literal(name), "sxe_snapshot->" + _literal(name)))
    caller_shapes = ""
    caller_lifetime = ""
    if delivery:
        caller = delivery_packet.caller
        caller_shapes = f"""
            {_signed_shape("sxe_documents->'callerEnrollment'", caller.ENROLLMENT_SCHEMA,
                caller.ENROLLMENT_FIELDS, caller.ENROLLMENT_PAYLOAD_SCHEMA)}
            {_signed_shape("sxe_documents->'callerAuthorization'", caller.REQUEST_SCHEMA,
                caller.REQUEST_FIELDS, caller.REQUEST_PAYLOAD_SCHEMA)}
            sxe_caller_enrollment := sxe_documents->'callerEnrollment'->'payload';
            sxe_caller := sxe_documents->'callerAuthorization'->'payload';
        """
        pairs += [("sxe_caller->" + _literal(name), "sxe_caller_enrollment->" + _literal(name))
            for name in caller._SCOPE_FIELDS]
        pairs += [("sxe_caller->" + _literal(name), "sxe_grant->" + _literal(name))
            for name in ("sourceRevision", "configurationDigest", "databaseId", "generationDigest",
                "operation", "requestDigest", "operationId", "planDigest", "retainedRecordDigest",
                "journalDigest", "beforeVectorDigest", "currentRootEnrollmentDigest", "grantEnrollmentDigest")]
        pairs += [("sxe_caller->'authorizationEnrollmentDigest'", "sxe_identities->'callerEnrollment'"),
            ("sxe_packet->'authorizationDigest'", "sxe_identities->'callerAuthorization'"),
            ("sxe_caller->'callerMeasurementDigest'", "sxe_caller_enrollment->'callerKey'->'measurementDigest'"),
            ("sxe_caller->'audienceSpkiDigest'", "sxe_grant_enrollment->'authorizer'->'spkiDigest'"),
            ("sxe_caller->>'purpose'", _literal(caller.PURPOSE)),
            ("sxe_caller_enrollment->>'purpose'", _literal(caller.PURPOSE)),
            ("sxe_caller_enrollment->>'operation'", _literal(delivery_packet.OPERATION)),
            ("sxe_grant_enrollment->>'operation'", _literal(delivery_packet.OPERATION))]
        caller_lifetime = f"""
            {_integer("sxe_caller->'issuedAtEpochNs'", minimum=1)}
            {_integer("sxe_caller->'expiresAtEpochNs'", minimum=1)}
            {_integer("sxe_caller_enrollment->'maximumAgeNs'", minimum=1,
                maximum=authority.VERIFIER_RESPONSE_MAX_AGE_NS)}
            {_integer("sxe_caller_enrollment->'maximumClockSkewNs'",
                maximum=authority.VERIFIER_MAX_CLOCK_SKEW_NS)}
            {_integer("sxe_grant_enrollment->'maximumGrantAgeNs'", minimum=1,
                maximum=authority.VERIFIER_RESPONSE_MAX_AGE_NS)}
            {_integer("sxe_grant_enrollment->'maximumClockSkewNs'",
                maximum=authority.VERIFIER_MAX_CLOCK_SKEW_NS)}
            {_integer("sxe_snapshot->'originalIssuedAtEpochNs'", minimum=1)}
            {_integer("sxe_snapshot->'originalExpiresAtEpochNs'", minimum=1)}
            IF (sxe_caller->>'issuedAtEpochNs')::bigint < sxe_issued
                OR (sxe_caller->>'expiresAtEpochNs')::bigint <= (sxe_caller->>'issuedAtEpochNs')::bigint
                OR (sxe_caller->>'expiresAtEpochNs')::bigint - (sxe_caller->>'issuedAtEpochNs')::bigint
                    > (sxe_caller_enrollment->>'maximumAgeNs')::bigint
                OR (sxe_caller->>'issuedAtEpochNs')::numeric >
                    pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000000)
                    + (sxe_caller_enrollment->>'maximumClockSkewNs')::bigint
                OR sxe_expires > (sxe_caller->>'expiresAtEpochNs')::bigint
                OR sxe_issued <> (sxe_snapshot->>'originalIssuedAtEpochNs')::bigint
                OR (sxe_caller->>'expiresAtEpochNs')::bigint > (sxe_snapshot->>'originalExpiresAtEpochNs')::bigint
                OR (sxe_grant->>'expiresAtEpochNs')::bigint > (sxe_snapshot->>'originalExpiresAtEpochNs')::bigint
                OR (sxe_grant->>'expiresAtEpochNs')::bigint - sxe_issued
                    > (sxe_grant_enrollment->>'maximumGrantAgeNs')::bigint
            THEN RAISE EXCEPTION 'consume packet retimes caller or original grant authority'; END IF;
        """
    return f"""
        {_signed_shape("sxe_documents->'currentRootEnrollment'", authorization.ENROLLMENT_SCHEMA,
            authorization.ENROLLMENT_FIELDS, authorization.ENROLLMENT_PAYLOAD_SCHEMA)}
        {_signed_shape("sxe_documents->'grantEnrollment'", grant_enrollment.ENROLLMENT_SCHEMA,
            grant_enrollment.ENROLLMENT_FIELDS, grant_enrollment.ENROLLMENT_PAYLOAD_SCHEMA)}
        {_signed_shape("sxe_documents->'grant'", grant_wire.GRANT_SCHEMA,
            grant_wire.GRANT_FIELDS, grant_wire.GRANT_PAYLOAD_SCHEMA)}
        {_signed_shape("sxe_documents->'reserveRequest'", authorization.REQUEST_SCHEMA,
            authorization.RESERVE_FIELDS, authorization.REQUEST_PAYLOAD_SCHEMA)}
        {_signed_shape("sxe_documents->'reserveReceipt'", authorization.RECEIPT_SCHEMA,
            authorization.RECEIPT_FIELDS, authorization.RECEIPT_PAYLOAD_SCHEMA)}
        sxe_enrollment := sxe_documents->'currentRootEnrollment'->'payload';
        sxe_grant_enrollment := sxe_documents->'grantEnrollment'->'payload';
        sxe_grant := sxe_documents->'grant'->'payload';
        sxe_reserve := sxe_documents->'reserveRequest'->'payload';
        sxe_receipt := sxe_documents->'reserveReceipt'->'payload';
        sxe_snapshot := sxe_documents->'computationSnapshot';
        {caller_shapes}
        IF NOT {_closed('sxe_snapshot', snapshot_fields)}
            OR sxe_snapshot->>'schema' IS DISTINCT FROM {_literal(snapshot.SNAPSHOT_SCHEMA)}
            OR sxe_snapshot->>'sourceRevision' IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
        THEN RAISE EXCEPTION 'successor original computation snapshot changed'; END IF;
        {_equal(pairs, 'successor packet original scope or marker commitments changed')}
        {_integer("sxe_enrollment->'maxRecords'", minimum=2, maximum=authorization.MAX_RECORDS)}
        {_integer("sxe_enrollment->'maxControlAgeNs'", minimum=1, maximum=authority.VERIFIER_RESPONSE_MAX_AGE_NS)}
        {_integer("sxe_enrollment->'maxClockSkewNs'", maximum=authority.VERIFIER_MAX_CLOCK_SKEW_NS)}
        {_integer("sxe_grant->'expiresAtEpochNs'", minimum=1)}
        {caller_lifetime}
        IF sxe_expires > (sxe_grant->>'expiresAtEpochNs')::bigint
            OR sxe_expires - sxe_issued > (sxe_enrollment->>'maxControlAgeNs')::bigint
            OR sxe_issued::numeric > pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000000)
                + (sxe_enrollment->>'maxClockSkewNs')::bigint
            OR (crx_marker->>'pending_sequence')::bigint >= (sxe_enrollment->>'maxRecords')::bigint
            OR (crx_marker->>'pending_sequence')::bigint <> (crx_marker->>'predecessor_sequence')::bigint + 1
        THEN RAISE EXCEPTION 'successor packet original interval or completion capacity changed'; END IF;
    """


def _packet(namespace):
    header, _heads, operations = effects._source()
    digest_fields = tuple("crx_marker->" + _literal(name)
        for name in authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS if name.endswith("_digest"))
    return f"""
        IF sxe_packet_text IS NULL OR pg_catalog.octet_length(sxe_packet_text) NOT BETWEEN 2 AND {packet.MAX_BYTES}
            OR pg_catalog.length(sxe_packet_text) IS DISTINCT FROM pg_catalog.octet_length(sxe_packet_text)
            OR sxe_packet_digest IS NULL OR sxe_packet_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
        THEN RAISE EXCEPTION 'successor canonical packet transport is not bounded'; END IF;
        sxe_packet := sxe_packet_text::jsonb;
        IF NOT {_closed('sxe_packet', packet.PACKET_FIELDS)}
            OR sxe_packet->>'schema' IS DISTINCT FROM {_literal(packet.SCHEMA)}
            OR sxe_packet->>'sourceRevision' IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
        THEN RAISE EXCEPTION 'successor custody packet shape changed'; END IF;
        {_wire(namespace, 'sxe_packet', 'sxe_canonical', packet.MAX_BYTES)}
        IF sxe_canonical IS DISTINCT FROM sxe_packet_text
            OR sxe_packet_digest IS DISTINCT FROM {_digest(namespace, packet.IDENTITY_DOMAIN, 'sxe_packet_text')}
        THEN RAISE EXCEPTION 'successor custody original packet identity changed'; END IF;
        {_digests(("sxe_packet->'authorizationDigest'", "sxe_packet->'requestDigest'", "sxe_packet->'operationId'"))}
        {_integer("sxe_packet->'issuedAtEpochNs'", minimum=1)}
        {_integer("sxe_packet->'expiresAtEpochNs'", minimum=1)}
        {_integer("sxe_packet->'workUnits'", minimum=1)}
        sxe_issued := (sxe_packet->>'issuedAtEpochNs')::bigint;
        sxe_expires := (sxe_packet->>'expiresAtEpochNs')::bigint;
        IF sxe_expires <= sxe_issued THEN RAISE EXCEPTION 'successor original interval is empty'; END IF;
        sxe_deadline := LEAST(sxe_deadline, sxe_expires);
        {_live()}
        crx_operation := sxe_packet->>'operation'; crx_request_digest := sxe_packet->>'requestDigest';
        crx_operation_id := sxe_packet->>'operationId'; crx_selected_rows := sxe_packet->'selectedRows';
        crx_mutations := sxe_packet->'mutations'; crx_work_units := (sxe_packet->>'workUnits')::bigint;
        crx_marker := sxe_packet->'marker';
        sxe_spec := {_literal(effects._json(operations))}::jsonb->crx_operation;
        IF sxe_spec IS NULL OR crx_operation_id IS DISTINCT FROM {namespace}.serverware_policy_authority_domain_digest(
                'serverware.policyAuthorityOperation/v2', crx_operation, crx_request_digest)
            OR pg_catalog.jsonb_typeof(crx_selected_rows) IS DISTINCT FROM 'array'
            OR pg_catalog.jsonb_typeof(crx_mutations) IS DISTINCT FROM 'array'
        THEN RAISE EXCEPTION 'successor custody operation or effects are outside source'; END IF;
        IF pg_catalog.jsonb_array_length(crx_selected_rows) > (sxe_spec->>'maximumQueryRows')::integer
            OR pg_catalog.jsonb_array_length(crx_mutations) > (sxe_spec->>'maximumMutations')::integer
            OR crx_work_units > (sxe_spec->>'maximumWorkUnits')::bigint
        THEN RAISE EXCEPTION 'successor custody effects exceed source bounds'; END IF;
        {_wire(namespace, 'crx_selected_rows', 'sxe_canonical', authority.MAX_PLAN_SELECTED_BYTES)}
        {_wire(namespace, 'crx_mutations', 'sxe_canonical', authority.MAX_RESULT_BYTES)}
        FOR sxe_document IN SELECT item.value FROM pg_catalog.jsonb_array_elements(crx_selected_rows) AS item(value) LOOP
            IF NOT {_closed('sxe_document', _SELECTED_FIELDS)}
                OR (sxe_spec->'keys' ? (sxe_document->>'table')) IS DISTINCT FROM TRUE
                OR pg_catalog.jsonb_typeof(sxe_document->'key') IS DISTINCT FROM 'object'
                OR pg_catalog.jsonb_typeof(sxe_document->'present') IS DISTINCT FROM 'boolean'
                OR pg_catalog.jsonb_typeof(sxe_document->'row') NOT IN ('object', 'null')
                OR pg_catalog.jsonb_typeof(sxe_document->'contractSelector') NOT IN ('string', 'null')
            THEN RAISE EXCEPTION 'successor selected custody record is not exact'; END IF;
            {_digests(("sxe_document->'keyDigest'",))}
        END LOOP;
        FOR sxe_document IN SELECT item.value FROM pg_catalog.jsonb_array_elements(crx_mutations) AS item(value) LOOP
            IF NOT {_closed('sxe_document', _MUTATION_FIELDS)}
                OR (sxe_spec->'writes' ? (sxe_document->>'table')) IS DISTINCT FROM TRUE
                OR sxe_spec->'templates'->(sxe_document->>'templateId') IS NULL
                OR sxe_spec->'templates'->(sxe_document->>'templateId')->>'table' IS DISTINCT FROM sxe_document->>'table'
                OR sxe_spec->'templates'->(sxe_document->>'templateId')->>'mutation' IS DISTINCT FROM sxe_document->>'operation'
                OR pg_catalog.jsonb_typeof(sxe_document->'key') IS DISTINCT FROM 'object'
                OR pg_catalog.jsonb_typeof(sxe_document->'expectedRow') NOT IN ('object', 'null')
                OR pg_catalog.jsonb_typeof(sxe_document->'row') NOT IN ('object', 'null')
            THEN RAISE EXCEPTION 'successor mutation custody record is not exact'; END IF;
            {_digests(("sxe_document->'keyDigest'",))}
        END LOOP;
        {_wire(namespace, "sxe_packet->'beforeVector'", 'crx_before_vector_json', vector.MAX_BYTES, vector.MAX_NODES, vector.MAX_DEPTH)}
        {_wire(namespace, "sxe_packet->'afterVector'", 'crx_after_vector_json', vector.MAX_BYTES, vector.MAX_NODES, vector.MAX_DEPTH)}
        {_wire(namespace, "sxe_packet->'result'", 'crx_result_json', authority.MAX_RESULT_BYTES)}
        IF NOT {_closed('crx_marker', authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS)}
            OR crx_marker->>'source_revision' IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
            OR pg_catalog.jsonb_typeof(crx_marker->'database_id') IS DISTINCT FROM 'string'
            OR crx_marker->>'database_id' COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{{0,127}}$'
        THEN RAISE EXCEPTION 'successor custody marker is not source closed'; END IF;
        {_digests((*digest_fields, "crx_marker->'operation_id'"))}
        {_integer("crx_marker->'pending_sequence'", minimum=1, maximum=authorization.MAX_RECORDS - 1)}
        {_integer("crx_marker->'predecessor_sequence'", maximum=authorization.MAX_RECORDS - 2)}
        {_integer("crx_marker->'fence'", minimum=1)}
        {_wire(namespace, 'crx_marker', 'crx_marker_json', 4096, 64, 2)}
        IF crx_marker->>'before_vector_digest' IS DISTINCT FROM {_digest(namespace, vector.IDENTITY_DOMAIN, 'crx_before_vector_json')}
            OR crx_marker->>'after_vector_digest' IS DISTINCT FROM {_digest(namespace, vector.IDENTITY_DOMAIN, 'crx_after_vector_json')}
            OR crx_marker->>'result_digest' IS DISTINCT FROM {_digest(namespace, 'serverware.policyAuthorityControlledWriterResult/v2', 'crx_result_json')}
            OR ((sxe_packet->'beforeVector') - 'primaryRoots' - 'countedRoots') IS DISTINCT FROM {_literal(effects._json(header))}::jsonb
            OR ((sxe_packet->'afterVector') - 'primaryRoots' - 'countedRoots') IS DISTINCT FROM {_literal(effects._json(header))}::jsonb
        THEN RAISE EXCEPTION 'successor custody result/vector commitments changed'; END IF;
        IF crx_operation = {_literal(delivery_packet.OPERATION)} THEN
            {_originals(namespace, delivery=True)}
            {_bindings(namespace, delivery=True)}
        ELSE
            {_originals(namespace)}
            {_bindings(namespace)}
        END IF;
        {_live()}
    """


def _pins(value):
    if type(value) is not tuple or len(value) != 6:
        raise ValueError("successor SQL identity must be an exact cold-pinned tuple6")
    for digest in value[:3]:
        if type(digest) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise ValueError("successor SQL measured identity pin is invalid")
    for name in (value[3], value[5]):
        if type(name) is not str or not name or "\x00" in name or len(name.encode("utf-8")) > 4096:
            raise ValueError("successor SQL TLS name is not bounded")
    if type(value[4]) is not str or re.fullmatch(r"[0-9A-Fa-f:]{1,256}", value[4]) is None:
        raise ValueError("successor SQL TLS serial is not exact")
    return value


def _admission(namespace, role, owner_role, pins, domain, *, recovery=False):
    return f"""
        IF session_user IS DISTINCT FROM {_literal(role)} OR current_user IS DISTINCT FROM {_literal(owner_role)}
            OR pg_catalog.current_setting('server_version_num')::integer / 10000 <> 16
            OR pg_catalog.current_setting('transaction_isolation') IS DISTINCT FROM 'serializable'
            OR pg_catalog.current_setting('transaction_read_only') IS DISTINCT FROM {_literal('on' if recovery else 'off')}
            OR pg_catalog.current_setting('transaction_deferrable') IS DISTINCT FROM {_literal('on' if recovery else 'off')}
        THEN RAISE EXCEPTION 'successor protected role or transaction is not exact'; END IF;
        SELECT setting::bigint INTO STRICT sxe_statement_ms FROM pg_catalog.pg_settings WHERE name = 'statement_timeout';
        SELECT setting::bigint INTO STRICT sxe_lock_ms FROM pg_catalog.pg_settings WHERE name = 'lock_timeout';
        SELECT setting::bigint INTO STRICT sxe_idle_ms FROM pg_catalog.pg_settings WHERE name = 'idle_in_transaction_session_timeout';
        IF sxe_statement_ms NOT BETWEEN 1 AND 2147483647 OR sxe_lock_ms NOT BETWEEN 1 AND 2147483647
            OR sxe_idle_ms NOT BETWEEN 1 AND 2147483647
        THEN RAISE EXCEPTION 'successor inherited waits must be finite and positive'; END IF;
        sxe_deadline := pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.statement_timestamp()) * 1000000000)
            + sxe_statement_ms::numeric * 1000000;
        {_live()}
        SELECT ssl, client_dn, client_serial::text, issuer_dn
            INTO STRICT sxe_tls, sxe_dn, sxe_serial, sxe_issuer_dn
            FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid();
        IF sxe_tls IS DISTINCT FROM TRUE OR sxe_dn IS DISTINCT FROM {_literal(pins[3])}
            OR sxe_serial IS DISTINCT FROM {_literal(pins[4])} OR sxe_issuer_dn IS DISTINCT FROM {_literal(pins[5])}
        THEN RAISE EXCEPTION 'successor protected TLS identity differs from cold pins'; END IF;
        -- Measured identity/credential pins are independently supplied by the
        -- cold installer and bound into this exact catalog-checked body. TLS
        -- admits that provisioned principal; SQL does not measure its process.
        sxe_session_identity := {namespace}.serverware_policy_authority_domain_digest(
            {_literal(domain)}, session_user, sxe_dn, sxe_serial, sxe_issuer_dn,
            {', '.join(_literal(value) for value in pins[:3])});
    """


def successor_execution_functions_sql(namespace: str, *, issuer_role: str, executor_role: str,
        recovery_role: str, owner_role: str, issuer_pins: tuple, executor_pins: tuple,
        recovery_pins: tuple) -> str:
    """Render fixed issue2/consume2/read2; caller owns install/ACL/catalog."""
    _schema_name(namespace)
    for role in (issuer_role, executor_role, recovery_role, owner_role):
        if type(role) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", role) is None:
            raise ValueError("successor SQL role is not a source-bounded identifier")
    if (len({issuer_role, executor_role, recovery_role, owner_role}) != 4
            or recovery_role != authority.SUCCESSOR_RECOVERY_ROLE):
        raise ValueError("successor issuer, executor, fixed recovery and owner must be distinct")
    issuer_pins, executor_pins, recovery_pins = _pins(issuer_pins), _pins(executor_pins), _pins(recovery_pins)
    if len({issuer_pins[3:], executor_pins[3:], recovery_pins[3:]}) != 3:
        raise ValueError("successor issuer, executor and recovery TLS principals must be distinct")
    if tuple(authority.SUCCESSOR_EXECUTION_CUSTODY_COLUMNS) != _COLUMNS:
        raise ValueError("successor SQL custody columns differ from the exact source contract")
    table = authority.SUCCESSOR_EXECUTION_CUSTODY_TABLE
    if table != "policy_authority_successor_execution_custody":
        raise ValueError("successor SQL custody table is not source fixed")
    issuer_identity = (f"{namespace}.serverware_policy_authority_domain_digest("
        + ", ".join(_literal(value) for value in (ISSUER_IDENTITY_DOMAIN, issuer_role,
            *issuer_pins[3:], *issuer_pins[:3])) + ")")
    common = f"""
        {effects.current_root_execution_declarations_sql()}
        sxe_row {namespace}.{table}%ROWTYPE;
        sxe_packet_text text; sxe_packet_digest text; sxe_packet jsonb; sxe_spec jsonb;
        sxe_canonical text; sxe_text text; sxe_raw bytea; sxe_signature bytea;
        sxe_documents jsonb; sxe_document jsonb; sxe_identities jsonb; sxe_control jsonb;
        sxe_enrollment jsonb; sxe_grant_enrollment jsonb; sxe_grant jsonb;
        sxe_caller_enrollment jsonb; sxe_caller jsonb;
        sxe_reserve jsonb; sxe_receipt jsonb; sxe_snapshot jsonb;
        sxe_plan_maxima jsonb; sxe_frames jsonb; sxe_frame jsonb;
        sxe_name text; sxe_domain text; sxe_maximum bigint; sxe_count bigint; sxe_position bigint;
        sxe_total bigint; sxe_issued bigint; sxe_expires bigint; sxe_deadline numeric;
        sxe_statement_ms bigint; sxe_lock_ms bigint; sxe_idle_ms bigint;
        sxe_tls boolean; sxe_dn text; sxe_serial text; sxe_issuer_dn text;
        sxe_issuer_identity text; sxe_session_identity text; sxe_measured record; sxe_rendered record;
    """
    bindings = {
        "pending_decision_digest": "crx_marker->>'pending_decision_digest'", "packet_digest": "sxe_packet_digest",
        "packet_json": "sxe_packet_text", "enrollment_digest": "crx_marker->>'enrollment_digest'",
        "generation_digest": "crx_marker->>'generation_digest'", "capability_digest": "crx_marker->>'capability_digest'",
        "operation_id": "crx_operation_id", "fence": "(crx_marker->>'fence')::bigint",
        "issued_at_epoch_ns": "sxe_issued", "expires_at_epoch_ns": "sxe_expires", "issuer_identity_digest": "sxe_issuer_identity"}
    exact_row = _equal([("sxe_row." + name, expression) for name, expression in bindings.items()],
        "successor immutable custody differs from its original packet or issuer")
    issue = f"""
        sxe_packet_text := supplied_packet_json; sxe_packet_digest := supplied_packet_digest;
        sxe_issuer_identity := {issuer_identity};
        IF sxe_session_identity IS DISTINCT FROM sxe_issuer_identity
        THEN RAISE EXCEPTION 'successor actual issuer session identity changed'; END IF;
        {_packet(namespace)}
        INSERT INTO {namespace}.{table} ({', '.join(_COLUMNS)}) VALUES ({', '.join(bindings[name] for name in _COLUMNS)})
            ON CONFLICT ON CONSTRAINT policy_authority_successor_execution_custody_pkey DO NOTHING;
        SELECT stored.* INTO STRICT sxe_row FROM {namespace}.{table} AS stored
            WHERE stored.pending_decision_digest = crx_marker->>'pending_decision_digest' FOR UPDATE;
        {exact_row}
        {_live()}
        RETURN QUERY SELECT sxe_row.pending_decision_digest, sxe_row.packet_digest,
            sxe_row.issued_at_epoch_ns, sxe_row.expires_at_epoch_ns;
    """
    execute = f"""
        IF supplied_pending_decision_digest IS NULL OR supplied_packet_digest IS NULL
            OR supplied_pending_decision_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
            OR supplied_packet_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
        THEN RAISE EXCEPTION 'successor execution selectors are not canonical identities'; END IF;
        SELECT stored.* INTO STRICT sxe_row FROM {namespace}.{table} AS stored
            WHERE stored.pending_decision_digest = supplied_pending_decision_digest FOR UPDATE;
        IF sxe_row.packet_digest IS DISTINCT FROM supplied_packet_digest
        THEN RAISE EXCEPTION 'successor protected packet selection changed'; END IF;
        sxe_packet_text := sxe_row.packet_json; sxe_packet_digest := sxe_row.packet_digest;
        sxe_issuer_identity := {issuer_identity};
        {_packet(namespace)}
        {exact_row}
        IF EXISTS (SELECT 1 FROM {namespace}.{authority.CURRENT_ROOT_COMMIT_MARKER_TABLE} AS used
                WHERE used.pending_decision_digest = supplied_pending_decision_digest)
        THEN RAISE EXCEPTION 'successor protected packet has already been consumed'; END IF;
        -- Only protected custody assigns effect locals. No caller JSON, token
        -- or legacy activation GUC can enter the source mutation body.
        crx_deadline_epoch_ns := LEAST(sxe_deadline, sxe_expires)::bigint;
        {effects.current_root_execution_apply_body_sql(namespace)}
        {_live()}
        RETURN crx_marker_json;
    """
    read = f"""
        IF supplied_pending_decision_digest IS NULL OR supplied_packet_digest IS NULL
            OR supplied_pending_decision_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
            OR supplied_packet_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
        THEN RAISE EXCEPTION 'successor recovery selectors are not canonical identities'; END IF;
        SELECT stored.* INTO STRICT sxe_row FROM {namespace}.{table} AS stored
            WHERE stored.pending_decision_digest = supplied_pending_decision_digest
              AND stored.packet_digest = supplied_packet_digest;
        sxe_packet_text := sxe_row.packet_json; sxe_packet_digest := supplied_packet_digest;
        IF sxe_packet_text IS NULL OR pg_catalog.octet_length(sxe_packet_text) NOT BETWEEN 2 AND {packet.MAX_BYTES}
            OR sxe_packet_text COLLATE "C" !~ '^[ -~]+$'
            OR {_digest(namespace, packet.IDENTITY_DOMAIN, 'sxe_packet_text')} IS DISTINCT FROM supplied_packet_digest
        THEN RAISE EXCEPTION 'successor recovery packet differs from its independent original identity'; END IF;
        sxe_packet := sxe_packet_text::jsonb;
        IF NOT {_closed('sxe_packet', packet.PACKET_FIELDS)}
            OR sxe_packet->>'schema' IS DISTINCT FROM {_literal(packet.SCHEMA)}
        THEN RAISE EXCEPTION 'successor recovery packet is not the closed source shape'; END IF;
        {_wire(namespace, 'sxe_packet', 'sxe_canonical', packet.MAX_BYTES)}
        IF sxe_canonical IS DISTINCT FROM sxe_packet_text
        THEN RAISE EXCEPTION 'successor recovery packet bytes are not canonical'; END IF;
        crx_marker := sxe_packet->'marker';
        IF NOT {_closed('crx_marker', authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS)}
        THEN RAISE EXCEPTION 'successor recovery marker is not closed'; END IF;
        {_digests(tuple("crx_marker->'" + name + "'" for name in
            ('pending_decision_digest', 'enrollment_digest', 'generation_digest', 'capability_digest', 'operation_id'))
            + ("sxe_packet->'operationId'",))}
        {_integer("crx_marker->'fence'", minimum=1)}
        {_integer("sxe_packet->'issuedAtEpochNs'", minimum=1, maximum=2**63 - 2)}
        {_integer("sxe_packet->'expiresAtEpochNs'", minimum=2)}
        crx_operation_id := sxe_packet->>'operationId';
        sxe_issued := (sxe_packet->>'issuedAtEpochNs')::bigint;
        sxe_expires := (sxe_packet->>'expiresAtEpochNs')::bigint;
        sxe_issuer_identity := {issuer_identity};
        IF sxe_expires <= sxe_issued OR crx_marker->>'operation_id' IS DISTINCT FROM crx_operation_id
        THEN RAISE EXCEPTION 'successor recovery original interval or operation changed'; END IF;
        {exact_row}
        -- Deliberately no _packet/live-control verifier, row lock, mutation or
        -- comparison of historical expiry to now. Only this read's inherited
        -- statement deadline remains live; downstream authenticates originals.
        {_live()}
        RETURN sxe_packet_text;
    """
    return "\n".join(textwrap.dedent(f"""
        CREATE OR REPLACE FUNCTION {namespace}.{name}({arguments})
        RETURNS {returns} LANGUAGE plpgsql SECURITY DEFINER VOLATILE
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $serverware_successor_custody$
        DECLARE
            {common}
        BEGIN
            {_admission(namespace, role, owner_role, pins, domain, recovery=role == recovery_role)}
            {body}
        END;
        $serverware_successor_custody$;
    """) for name, arguments, returns, role, pins, domain, body in (
        (ISSUE_FUNCTION, "supplied_packet_json text, supplied_packet_digest text",
            "TABLE(pending_decision_digest text, packet_digest text, issued_at_epoch_ns bigint, expires_at_epoch_ns bigint)",
            issuer_role, issuer_pins, ISSUER_IDENTITY_DOMAIN, issue),
        (EXECUTE_FUNCTION, "supplied_pending_decision_digest text, supplied_packet_digest text", "text",
            executor_role, executor_pins, EXECUTOR_IDENTITY_DOMAIN, execute),
        (READ_FUNCTION, "supplied_pending_decision_digest text, supplied_packet_digest text", "text",
            recovery_role, recovery_pins, RECOVERY_IDENTITY_DOMAIN, read)))
