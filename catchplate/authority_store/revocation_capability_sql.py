"""Private, fixed issuer custody functions for original revocation-v4 bytes.

These SECURITY DEFINER functions admit the pinned issuer session and bind
original transports to locked storage. They do NOT verify Ed25519, replay
proofs, enroll keys, provide a post-plan witness bind, or execute revocation.
The private owner must perform genuine verification between load and issue in
the same SERIALIZABLE read-write transaction. There are no table grants here.
SQL/driver parsing and encoding are outside Python H/B/N accounting. Wire
walks bound post-parse work, not the PostgreSQL parser's allocation. Lock waits
(including uniqueness/FK waits) are bounded; deadlock freedom is not claimed.
"""
from __future__ import annotations

import re
import textwrap

from catchplate import authority_contract as authority
from catchplate import authority_revocation_capability as capability
from catchplate.authority_store import authorization_records, revocation_execution, revocation_retention
from catchplate.authority_store.mutation_sql import _schema_name
from catchplate.authority_store.revocation_retained_sql import (
    _closed, _integers, _literal, _wire,
    load_revocation_retained_sql, revocation_retained_declarations_sql,
)


POSTGRES_MAJOR = 16
LOCK_TIMEOUT = "500ms"
STATEMENT_TIMEOUT = "5s"
LOAD_FUNCTION = "catchplate_policy_authority_load_revocation_issuance"
ISSUE_FUNCTION = "catchplate_policy_authority_issue_revocation_capability"
_WITNESS_FIELDS = (
    "witness_receipt_digest", "witness_identity_digest", "witness_sequence",
    "witness_head_digest", "predecessor_head_digest", "predecessor_receipt_digest",
    "log_predecessor_head_digest", "phase", "operation", "request_digest",
    "capability_id", "result_digest", "fence", "receipt_json", "recorded_at_epoch_ns",
)
_CAPABILITY_FIELDS = authority.WRITER_CAPABILITY_IMMUTABLE_COLUMNS + authority.WRITER_CAPABILITY_TERMINAL_COLUMNS
_ISSUER_ARGUMENTS = (
    "supplied_issuer_measurement_digest", "supplied_issuer_attestation_receipt_digest",
    "supplied_issuer_credential_issuance_digest",
)


def _object(values):
    return "pg_catalog.jsonb_build_object(" + ", ".join(
        _literal(name) + ", " + value for name, value in values.items()) + ")"


def _row(alias, fields):
    return _object({name: alias + "." + name for name in fields})


def _digest(namespace, domain, expression):
    return (f"{namespace}.catchplate_policy_authority_domain_digest("
            f"{_literal(domain)}, {expression})")


def _json_fields(value, fields):
    return _object({name: value + "->" + _literal(name) for name in fields})


def _require_digests(expressions):
    return "\n".join(f"""
        IF {expression} IS NULL OR {expression} COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
        THEN RAISE EXCEPTION 'revocation issuer digest input is invalid'; END IF;
    """ for expression in expressions)


def _transport(namespace, supplied, prefix, maximum):
    # Expressions and prefixes are only source literals at the two call sites.
    return f"""
        IF {supplied} IS NULL OR pg_catalog.length({supplied}) NOT BETWEEN 3 AND {(4 * maximum + 2) // 3}
            OR {supplied} COLLATE "C" !~ '^[A-Za-z0-9_-]+$'
            OR pg_catalog.length({supplied}) % 4 = 1
        THEN RAISE EXCEPTION 'revocation issuer original transport is invalid'; END IF;
        {prefix}_bytes := pg_catalog.decode(pg_catalog.translate({supplied}, '-_', '+/')
            || pg_catalog.repeat('=', (4 - pg_catalog.length({supplied}) % 4) % 4), 'base64');
        IF pg_catalog.octet_length({prefix}_bytes) NOT BETWEEN 2 AND {maximum}
            OR pg_catalog.translate(pg_catalog.encode({prefix}_bytes, 'base64'), E'+/=\\n\\r', '-_')
                IS DISTINCT FROM {supplied}
        THEN RAISE EXCEPTION 'revocation issuer original transport is not exact'; END IF;
        {prefix}_text := pg_catalog.convert_from({prefix}_bytes, 'UTF8');
        IF pg_catalog.octet_length({prefix}_text) IS DISTINCT FROM pg_catalog.length({prefix}_text)
        THEN RAISE EXCEPTION 'revocation issuer original transport is not ASCII'; END IF;
        {prefix} := {prefix}_text::pg_catalog.jsonb;
        {_wire(namespace, prefix, 'rvi_canonical', size=maximum, nodes=4096, depth=16)}
        IF pg_catalog.convert_to(rvi_canonical, 'UTF8') IS DISTINCT FROM {prefix}_bytes
        THEN RAISE EXCEPTION 'revocation issuer original JSON is not canonical'; END IF;
    """


def _signature(expression):
    return f"""
        IF pg_catalog.jsonb_typeof({expression}) IS DISTINCT FROM 'string'
            OR ({expression} #>> '{{}}') COLLATE "C" !~ '^[A-Za-z0-9_-]{{86}}$'
        THEN RAISE EXCEPTION 'revocation issuer signature transport is invalid'; END IF;
        rvi_signature := pg_catalog.decode(pg_catalog.translate({expression} #>> '{{}}', '-_', '+/') || '==', 'base64');
        IF pg_catalog.octet_length(rvi_signature) <> 64
            OR pg_catalog.translate(pg_catalog.encode(rvi_signature, 'base64'), E'+/=\\n\\r', '-_')
                IS DISTINCT FROM ({expression} #>> '{{}}')
        THEN RAISE EXCEPTION 'revocation issuer signature transport is not exact'; END IF;
    """


def _declarations(namespace):
    rows = {
        "planner": "policy_authority_planner_transactions",
        "execution_row": "policy_authority_execution_envelopes",
        "assertion_row": "policy_authority_webauthn_assertion_evidence",
        "projection_row": "policy_authority_authorization_projections",
        "capability_row": "policy_authority_writer_capabilities",
        "retained_capability_row": authority.REVOCATION_RETAINED_CAPABILITY_TABLE,
        "witness_row": "policy_authority_external_witness_receipts",
        "fence_row": "policy_authority_fence_heads",
    }
    return revocation_retained_declarations_sql() + "\n" + "\n".join(
        f"{name} {namespace}.{table}%ROWTYPE;" for name, table in rows.items()) + """
        rvi_capability_present boolean;
        rvi_retained_present boolean;
        rvi_witness_present boolean;
        rvi_candidates pg_catalog.jsonb;
        rvi_planner_id text; rvi_execution_id text; rvi_capability_id text;
        rvi_tls_active boolean; rvi_tls_dn text; rvi_tls_serial text; rvi_tls_issuer text;
        rvi_issuer_identity text; rvi_now numeric; rvi_count bigint;
        rvi_canonical text; rvi_execution_text text; rvi_execution_bytes bytea;
        rvi_envelope pg_catalog.jsonb; rvi_envelope_text text; rvi_envelope_bytes bytea;
        rvi_request pg_catalog.jsonb; rvi_request_text text; rvi_request_bytes bytea;
        rvi_capability pg_catalog.jsonb; rvi_receipt pg_catalog.jsonb;
        rvi_evidence pg_catalog.jsonb; rvi_projection pg_catalog.jsonb;
        rvi_evidence_text text; rvi_projection_text text; rvi_reads_text text; rvi_rows_text text;
        rvi_expected_assertion pg_catalog.jsonb; rvi_expected_projection pg_catalog.jsonb;
        rvi_challenge pg_catalog.jsonb; rvi_credential pg_catalog.jsonb;
        rvi_webauthn pg_catalog.jsonb; rvi_webauthn_text text; rvi_receipt_text text;
        rvi_expected_payload pg_catalog.jsonb; rvi_header pg_catalog.jsonb;
        rvi_expected_capability pg_catalog.jsonb; rvi_expected_retained pg_catalog.jsonb;
        rvi_expected_witness pg_catalog.jsonb; rvi_capability_digest text;
        rvi_witness_digest text; rvi_record_digest text; rvi_signature bytea;
    """


def _authorization(namespace):
    evidence_names = (
        "operation", "operationId", "requestDigest", "capabilityId", "challengeId",
        "challengeDigest", "clientChallengeDigest", "credentialRecordId", "credentialId",
        "credentialPolicyDigest", "authenticatorDataBase64url", "authenticatorDataDigest",
        "clientDataJSONBase64url", "clientDataJSONDigest", "signatureBase64url", "signatureDigest",
        "rpId", "rpIdHashDigest", "origin", "flags",
    )
    evidence = {"assertion_evidence_digest": "projection_row.assertion_evidence_digest"}
    evidence.update({column: "rvi_evidence->" + _literal(name)
        for column, name in zip(authorization_records._ASSERTION_FIELDS[1:21], evidence_names)})
    evidence.update({"user_present": "1", "user_verified": "1"})
    evidence.update({column: "rvi_evidence->" + _literal(name) for column, name in (
        ("prior_counter", "priorCounter"), ("counter", "counter"),
        ("trust_high_water_digest", "trustHighWaterDigest"), ("metadata_publication_sequence", "metadataPublicationSequence"),
        ("verifier_session_identity_digest", "verifierSessionIdentityDigest"), ("verifier_measurement_digest", "verifierMeasurementDigest"),
        ("verifier_attestation_receipt_digest", "verifierAttestationReceiptDigest"),
        ("verified_assertion_receipt_digest", "verifiedAssertionReceiptDigest"),
        ("verified_at_epoch_ns", "verifiedAtEpochNs"), ("expires_at_epoch_ns", "expiresAtEpochNs"))})
    evidence.update({"evidence_json": "rvi_evidence_text", "source_revision": _literal(authority.SOURCE_REVISION)})
    projection = {column: "rvi_projection->" + _literal(name) for column, name in (
        ("planner_transaction_id", "plannerTransactionId"), ("operation", "operation"),
        ("operation_id", "operationId"), ("request_digest", "requestDigest"), ("capability_id", "capabilityId"),
        ("source_high_water_digest", "sourceHighWaterDigest"), ("approver_policy_digest", "approverPolicyDigest"),
        ("assertion_evidence_digest", "assertionEvidenceDigest"),
        ("verifier_session_identity_digest", "verifierSessionIdentityDigest"), ("verifier_measurement_digest", "verifierMeasurementDigest"),
        ("verifier_attestation_receipt_digest", "verifierAttestationReceiptDigest"),
        ("created_at_epoch_ns", "createdAtEpochNs"), ("expires_at_epoch_ns", "expiresAtEpochNs"))}
    projection.update({"authorization_projection_digest": "planner.authorization_projection_digest",
        "operation_contract_digest": _literal(authority.OPERATION_MANIFEST_DIGEST),
        "authorization_reads_json": "rvi_reads_text", "authorization_reads_digest": _digest(namespace, "catchplate.policyAuthorityAuthorizationReads/v1", "rvi_reads_text"),
        "source_rows_json": "rvi_rows_text", "source_rows_digest": _digest(namespace, "catchplate.policyAuthorityAuthorizationRows/v1", "rvi_rows_text"),
        "projection_json": "rvi_projection_text", "source_revision": _literal(authority.SOURCE_REVISION)})
    return f"""
        rvi_evidence := rv_payload->'webauthnEvidence';
        rvi_projection := rv_payload->'authorizationProjection';
        SELECT * INTO STRICT projection_row FROM {namespace}.policy_authority_authorization_projections
            WHERE authorization_projection_digest = planner.authorization_projection_digest;
        SELECT * INTO STRICT assertion_row FROM {namespace}.policy_authority_webauthn_assertion_evidence
            WHERE assertion_evidence_digest = rvi_projection->>'assertionEvidenceDigest';
        {_wire(namespace, 'rvi_evidence', 'rvi_evidence_text', size=authority.MAX_REQUEST_BYTES)}
        {_wire(namespace, 'rvi_projection', 'rvi_projection_text', size=authority.MAX_REQUEST_BYTES)}
        {_wire(namespace, "rvi_projection->'authorizationReads'", 'rvi_reads_text', size=authority.MAX_REQUEST_BYTES)}
        {_wire(namespace, "rvi_projection->'sourceRows'", 'rvi_rows_text', size=authority.MAX_REQUEST_BYTES)}
        rvi_expected_assertion := {_object(evidence)};
        rvi_expected_projection := {_object(projection)};
        IF {_row('assertion_row', authorization_records._ASSERTION_FIELDS)} IS DISTINCT FROM rvi_expected_assertion
            OR {_row('projection_row', authorization_records._PROJECTION_FIELDS)} IS DISTINCT FROM rvi_expected_projection
            OR rvi_evidence->'userPresent' IS DISTINCT FROM 'true'::pg_catalog.jsonb
            OR rvi_evidence->'userVerified' IS DISTINCT FROM 'true'::pg_catalog.jsonb
        THEN RAISE EXCEPTION 'revocation issuer authorization custody changed'; END IF;
    """


def _custody(namespace):
    parent_nulls = " OR ".join("planner." + name + " IS NOT NULL"
        for name in authority.PLANNER_TERMINAL_IMMUTABLE_COLUMNS if name != "status")
    execution_nulls = " OR ".join("execution_row." + name + " IS NOT NULL"
                                   for name in revocation_execution._TERMINAL_FIELDS)
    capability_nulls = " OR ".join("capability_row." + name + " IS NOT NULL"
        for name in authority.WRITER_CAPABILITY_TERMINAL_COLUMNS if name != "status")
    execution_joins = " OR ".join(f"execution_row.{name} IS DISTINCT FROM planner.{name}" for name in (
        "planner_transaction_id", "operation", "operation_id", "request_digest", "capability_id",
        "authorization_projection_digest", "operation_contract_digest", "deadline_monotonic_ns",
        "deadline_epoch_ns", "fence", "reserved_at_epoch_ns", "source_revision"))
    return f"""
        SELECT * INTO STRICT fence_row FROM {namespace}.policy_authority_fence_heads
            WHERE authority_scope = 'controlled-writer' FOR UPDATE;
        SELECT * INTO capability_row FROM {namespace}.policy_authority_writer_capabilities
            WHERE capability_id = rvi_capability_id FOR UPDATE NOWAIT;
        rvi_capability_present := FOUND;
        IF rvi_capability_present AND (capability_row.capability_protocol IS DISTINCT FROM 'revocation-v4'
            OR capability_row.capability_record_digest IS NULL OR capability_row.status IS DISTINCT FROM 'issued'
            OR {capability_nulls})
        THEN RAISE EXCEPTION 'revocation issuer capability is not an unused issued record'; END IF;
        SELECT * INTO STRICT planner FROM {namespace}.policy_authority_planner_transactions
            WHERE planner_transaction_id = rvi_planner_id FOR UPDATE;
        IF planner.status IS DISTINCT FROM 'planned' OR planner.plan_protocol IS DISTINCT FROM 'revocation-v4'
            OR planner.operation IS DISTINCT FROM {_literal(capability.OPERATION)}
            OR planner.capability_id IS DISTINCT FROM rvi_capability_id
            OR planner.source_revision IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
            OR planner.retained_record_digest IS NULL OR {parent_nulls}
        THEN RAISE EXCEPTION 'revocation issuer planner is not exact planned custody'; END IF;
        SELECT * INTO STRICT execution_row FROM {namespace}.policy_authority_execution_envelopes
            WHERE envelope_id = rvi_execution_id FOR UPDATE;
        IF execution_row.status IS DISTINCT FROM 'reserved' OR execution_row.purpose IS DISTINCT FROM 'execute-v9'
            OR execution_row.parent_envelope_id IS DISTINCT FROM rvi_planner_id
            OR {execution_joins} OR {execution_nulls}
        THEN RAISE EXCEPTION 'revocation issuer execution reservation changed'; END IF;
        {load_revocation_retained_sql(namespace)}
        {_wire(namespace, _object({'schema': _literal(capability.EXECUTION_REQUEST_SCHEMA), 'planProtocol': "'revocation-v4'", 'retainedRecordDigest': 'rv_record_digest', 'rootTransitionDigest': "rv_plan->'rootTransitionDigest'", 'typedRequest': "rv_payload->'typedRequest'"}), 'rvi_execution_text', size=authority.MAX_REQUEST_BYTES)}
        rvi_execution_bytes := pg_catalog.convert_to(rvi_execution_text, 'UTF8');
        IF execution_row.exact_request_byte_count IS DISTINCT FROM pg_catalog.octet_length(rvi_execution_bytes)
            OR execution_row.exact_request_bytes_digest IS DISTINCT FROM
                'sha256:' || pg_catalog.encode(pg_catalog.sha256(rvi_execution_bytes), 'hex')
            OR execution_row.exact_request_base64url IS DISTINCT FROM
                pg_catalog.translate(pg_catalog.encode(rvi_execution_bytes, 'base64'), E'+/=\\n\\r', '-_')
        THEN RAISE EXCEPTION 'revocation issuer original execution bytes changed'; END IF;
        {_authorization(namespace)}
        SELECT * INTO retained_capability_row FROM {namespace}.{authority.REVOCATION_RETAINED_CAPABILITY_TABLE}
            WHERE capability_id = rvi_capability_id;
        rvi_retained_present := FOUND;
        IF rvi_capability_present IS DISTINCT FROM rvi_retained_present
        THEN RAISE EXCEPTION 'revocation issuer capability custody is incomplete'; END IF;
        SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(candidate)) INTO rvi_candidates FROM (
            SELECT * FROM {namespace}.policy_authority_external_witness_receipts
            WHERE capability_id = rvi_capability_id AND phase = 'reserve'
            ORDER BY witness_sequence LIMIT 2) AS candidate;
        IF COALESCE(pg_catalog.jsonb_array_length(rvi_candidates), 0) > 1
        THEN RAISE EXCEPTION 'revocation issuer preliminary witness custody is ambiguous'; END IF;
        rvi_witness_present := rvi_candidates IS NOT NULL;
        IF rvi_witness_present THEN
            SELECT * INTO STRICT witness_row FROM {namespace}.policy_authority_external_witness_receipts
                WHERE witness_receipt_digest = rvi_candidates->0->>'witness_receipt_digest';
            IF witness_row.operation IS DISTINCT FROM planner.operation
                OR witness_row.request_digest IS DISTINCT FROM planner.request_digest
                OR witness_row.result_digest IS NOT NULL OR witness_row.predecessor_head_digest IS NOT NULL
                OR witness_row.predecessor_receipt_digest IS NOT NULL OR witness_row.fence IS DISTINCT FROM planner.fence
            THEN RAISE EXCEPTION 'revocation issuer preliminary witness custody changed'; END IF;
        END IF;
        IF rvi_capability_present AND (NOT rvi_witness_present
            OR capability_row.planner_transaction_id IS DISTINCT FROM rvi_planner_id
            OR capability_row.envelope_id IS DISTINCT FROM rvi_execution_id
            OR capability_row.witness_reservation_digest IS DISTINCT FROM witness_row.witness_receipt_digest
            OR retained_capability_row.capability_record_digest IS DISTINCT FROM capability_row.capability_record_digest
            OR retained_capability_row.planner_transaction_id IS DISTINCT FROM rvi_planner_id
            OR retained_capability_row.execution_envelope_id IS DISTINCT FROM rvi_execution_id
            OR retained_capability_row.retained_record_digest IS DISTINCT FROM rv_record_digest)
        THEN RAISE EXCEPTION 'revocation issuer original issued custody changed'; END IF;
        rvi_now := EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000000;
        IF rvi_now >= planner.deadline_epoch_ns OR rvi_now < 0
        THEN RAISE EXCEPTION 'revocation issuer reservation deadline expired'; END IF;
    """


def _witness(namespace):
    joins = " OR ".join(f"rvi_receipt->{_literal(name)} IS DISTINCT FROM rvi_request->{_literal(name)}"
        for name in ("envelopeId", "parentEnvelopeId", "phase", "operation", "requestDigest", "capabilityId",
                     "resultDigest", "predecessorReceiptDigest", "deadlineMonotonicNs", "generationSequence", "generationDigest"))
    digests = tuple("rvi_request->>" + _literal(name) for name in (
        "envelopeId", "requestDigest", "capabilityId", "configurationDigest", "operationManifestDigest", "generationDigest"))
    digests += tuple("rvi_receipt->>" + _literal(name) for name in (
        "witnessIdentityDigest", "headDigest", "canonicalRequestDigest"))
    return f"""
        rvi_receipt := rvi_capability->'witnessReservation';
        IF NOT {_closed('rvi_request', capability.WITNESS_REQUEST_FIELDS)}
            OR NOT {_closed('rvi_receipt', capability.WITNESS_RECEIPT_FIELDS)}
            OR rvi_request->>'schema' IS DISTINCT FROM {_literal(capability.WITNESS_REQUEST_SCHEMA)}
            OR rvi_receipt->>'schema' IS DISTINCT FROM {_literal(capability.WITNESS_RECEIPT_SCHEMA)}
            OR rvi_request->>'phase' IS DISTINCT FROM 'reserve'
            OR rvi_request->>'operation' IS DISTINCT FROM planner.operation
            OR rvi_request->>'capabilityId' IS DISTINCT FROM planner.capability_id
            OR rvi_request->>'requestDigest' IS DISTINCT FROM planner.request_digest
            OR rvi_request->>'operationManifestDigest' IS DISTINCT FROM {_literal(authority.OPERATION_MANIFEST_DIGEST)}
            OR rvi_request->'deadlineMonotonicNs' IS DISTINCT FROM pg_catalog.to_jsonb(planner.deadline_monotonic_ns)
            OR rvi_receipt->'fence' IS DISTINCT FROM pg_catalog.to_jsonb(planner.fence)
            OR rvi_request->'parentEnvelopeId' IS DISTINCT FROM 'null'::pg_catalog.jsonb
            OR rvi_request->'resultDigest' IS DISTINCT FROM 'null'::pg_catalog.jsonb
            OR rvi_request->'predecessorReceiptDigest' IS DISTINCT FROM 'null'::pg_catalog.jsonb
            OR rvi_receipt->'predecessorHeadDigest' IS DISTINCT FROM 'null'::pg_catalog.jsonb
            OR {joins}
        THEN RAISE EXCEPTION 'revocation issuer preliminary witness binding changed'; END IF;
        {_require_digests(digests)}
        IF rvi_receipt->'logPredecessorHeadDigest' IS DISTINCT FROM 'null'::pg_catalog.jsonb THEN
            {_require_digests(("rvi_receipt->>'logPredecessorHeadDigest'",))}
        END IF;
        {_integers('rvi_request', ('deadlineMonotonicNs', 'issuedAtEpochNs', 'generationSequence'))}
        {_integers('rvi_receipt', ('deadlineMonotonicNs', 'issuedAtEpochNs', 'generationSequence', 'sequence', 'fence'))}
        {_signature("rvi_envelope->'signatureBase64Url'")}
        {_signature("rvi_request->'signature'")}
        {_signature("rvi_receipt->'signature'")}
        {_wire(namespace, _json_fields('rvi_request', ('phase', 'operation', 'requestDigest', 'capabilityId', 'resultDigest', 'predecessorReceiptDigest', 'generationSequence', 'generationDigest')), 'rvi_canonical', size=65536, nodes=4096, depth=16)}
        IF rvi_request->>'envelopeId' IS DISTINCT FROM {_digest(namespace, capability.WITNESS_ENVELOPE_SCHEMA, 'rvi_canonical')}
            OR rvi_receipt->>'canonicalRequestDigest' IS DISTINCT FROM {_digest(namespace, capability.WITNESS_REQUEST_SCHEMA, 'rvi_request_text')}
        THEN RAISE EXCEPTION 'revocation issuer witness request commitment changed'; END IF;
        {_wire(namespace, "(rvi_receipt - 'signature') || pg_catalog.jsonb_build_object('headDigest', NULL)", 'rvi_canonical', size=4194304, nodes=4096, depth=16)}
        IF rvi_receipt->>'headDigest' IS DISTINCT FROM {_digest(namespace, capability.WITNESS_HEAD_SCHEMA, 'rvi_canonical')}
        THEN RAISE EXCEPTION 'revocation issuer witness head commitment changed'; END IF;
        {_wire(namespace, 'rvi_receipt', 'rvi_receipt_text', size=4194304, nodes=4096, depth=16)}
        rvi_witness_digest := {_digest(namespace, capability.WITNESS_RECEIPT_SCHEMA, 'rvi_receipt_text')};
    """


def _expected(namespace):
    payload = {name: "rv_plan->" + _literal(name) for name in (
        "capabilityId", "plannerTransactionId", "authorizationProjectionDigest", "selectedBusinessRowsDigest",
        "mutationPlanDigest", "operationId", "requestDigest", "queryManifestDigest", "authoritySnapshotDigest",
        "deadlineMonotonicNs", "deadlineEpochNs", "fence", "rootTransitionDigest")}
    payload.update({"schema": _literal(capability.CAPABILITY_SCHEMA), "envelopeId": "rvi_execution_id",
        "operation": _literal(capability.OPERATION), "handlerName": _literal(authority.operation_spec(capability.OPERATION)["handler"]),
        "operationManifestDigest": "rv_plan->'operationManifestDigest'", "authorityRootSetDigest": "rv_plan->'authorityRootSetBeforeDigest'",
        "approverPolicyDigest": "rvi_projection->'approverPolicyDigest'", "expectedResultDigest": "rv_payload->'expectedResultDigest'",
        "webauthnReceipt": "rvi_webauthn", "webauthnReceiptDigest": _digest(namespace, capability.WEBAUTHN_RECEIPT_SCHEMA, "rvi_webauthn_text"),
        "webauthnTrustHighWaterDigest": "rvi_evidence->'trustHighWaterDigest'", "witnessReservation": "rvi_receipt",
        "witnessReservationDigest": "rvi_witness_digest", "witnessSequence": "rvi_receipt->'sequence'",
        "witnessHeadDigest": "rvi_receipt->'headDigest'", "witnessPredecessorHeadDigest": "NULL",
        "issuedAtEpochNs": "planner.reserved_at_epoch_ns",
        "issuedMonotonicNs": "planner.deadline_monotonic_ns::numeric - (planner.deadline_epoch_ns::numeric - planner.reserved_at_epoch_ns::numeric)",
        "expiresAtEpochNs": "planner.deadline_epoch_ns", "issuerSessionIdentityDigest": "rvi_issuer_identity",
        "planProtocol": "'revocation-v4'", "retainedRecordDigest": "rv_record_digest",
        "exactRequestBytesDigest": "execution_row.exact_request_bytes_digest"})
    receipt = {name: "rvi_evidence->" + _literal(name) for name in capability._RECEIPT_EVIDENCE_FIELDS}
    receipt.update({"schema": _literal(capability.WEBAUTHN_RECEIPT_SCHEMA),
        "challengeRowDigest": _digest(namespace, "catchplate.policyAuthorityWebAuthnChallengeRow/v1", "rvi_canonical"),
        "credentialBindingDigest": f"{namespace}.catchplate_policy_authority_framed_digest('catchplate.policyAuthorityWebAuthnCredentialBinding/v1', rvi_webauthn_text)"})
    return f"""
        SELECT value->'expectedRow' INTO STRICT rvi_challenge FROM pg_catalog.jsonb_array_elements(rv_payload->'mutationPlan')
            WHERE value->>'table' = 'webauthn_challenges'
                AND value->'key' = pg_catalog.jsonb_build_object('id', rvi_evidence->'challengeId');
        SELECT value->'expectedRow' INTO STRICT rvi_credential FROM pg_catalog.jsonb_array_elements(rv_payload->'mutationPlan')
            WHERE value->>'table' = 'webauthn_credentials'
                AND value->'key' = pg_catalog.jsonb_build_object('id', rvi_evidence->'credentialRecordId');
        IF pg_catalog.jsonb_typeof(rvi_challenge) IS DISTINCT FROM 'object'
            OR pg_catalog.jsonb_typeof(rvi_credential) IS DISTINCT FROM 'object'
        THEN RAISE EXCEPTION 'revocation issuer original receipt rows are absent'; END IF;
        {_wire(namespace, _json_fields('rvi_challenge', capability._CHALLENGE_FIELDS), 'rvi_canonical', size=4194304, nodes=4096, depth=16)}
        {_wire(namespace, _json_fields('rvi_credential', capability._CREDENTIAL_FIELDS), 'rvi_webauthn_text', size=4194304, nodes=4096, depth=16)}
        rvi_webauthn := {_object(receipt)};
        {_wire(namespace, 'rvi_webauthn', 'rvi_webauthn_text', size=4194304, nodes=4096, depth=16)}
        rvi_expected_payload := {_object(payload)};
        IF rvi_capability IS DISTINCT FROM rvi_expected_payload
        THEN RAISE EXCEPTION 'revocation issuer capability payload binding changed'; END IF;
        {_integers('rvi_capability', tuple(sorted(capability._CAPABILITY_INTEGERS)))}
        {_wire(namespace, 'rvi_capability', 'rvi_canonical', size=4194304, nodes=4096, depth=16)}
        rvi_capability_digest := {_digest(namespace, capability.CAPABILITY_SCHEMA, 'rvi_canonical')};
    """


def _storage(namespace):
    # Exact column recipes. SQL never substitutes a parsed/reserialized
    # envelope or witness request for either supplied original transport.
    header = {"schema": _literal(capability.RECORD_SCHEMA), "sourceRevision": _literal(authority.SOURCE_REVISION),
        "capabilityProtocol": "'revocation-v4'", "capabilityId": "rvi_capability_id", "plannerTransactionId": "rvi_planner_id",
        "executionEnvelopeId": "rvi_execution_id", "retainedRecordDigest": "rv_record_digest",
        "rootTransitionDigest": "rv_plan->'rootTransitionDigest'", "authoritySnapshotDigest": "rv_snapshot_digest",
        "exactRequestBytesDigest": "execution_row.exact_request_bytes_digest", "capabilityDigest": "rvi_capability_digest",
        "signerKeyDigest": "supplied_signer_key_digest", "witnessKeyDigest": "supplied_witness_key_digest",
        "envelopeDigest": "'sha256:' || pg_catalog.encode(pg_catalog.sha256(rvi_envelope_bytes), 'hex')",
        "envelopeByteCount": "pg_catalog.octet_length(rvi_envelope_bytes)",
        "witnessRequestBytesDigest": "'sha256:' || pg_catalog.encode(pg_catalog.sha256(rvi_request_bytes), 'hex')",
        "witnessRequestByteCount": "pg_catalog.octet_length(rvi_request_bytes)"}
    cap_names = (
        "capabilityId", None, None, None, "envelopeId", "operation", "operationId", "handlerName", "requestDigest",
        "operationManifestDigest", "queryManifestDigest", "authorityRootSetDigest", "authoritySnapshotDigest",
        "approverPolicyDigest", None, "webauthnReceiptDigest", "webauthnTrustHighWaterDigest", "witnessReservationDigest",
        "witnessSequence", "witnessHeadDigest", "deadlineMonotonicNs", "fence", "issuedMonotonicNs", "issuedAtEpochNs",
        "expiresAtEpochNs", "issuerSessionIdentityDigest", None, None, None, "expectedResultDigest", "plannerTransactionId",
        "authorizationProjectionDigest", "selectedBusinessRowsDigest", "mutationPlanDigest", "deadlineEpochNs")
    cap_values = {column: "rvi_capability->" + _literal(name) for column, name in
        zip(authority.WRITER_CAPABILITY_IMMUTABLE_COLUMNS, cap_names) if name is not None}
    cap_values.update({"capability_protocol": "'revocation-v4'", "capability_record_digest": "rvi_record_digest",
        "capability_digest": "rvi_capability_digest", "webauthn_receipt_json": "rvi_webauthn_text",
        "issuer_measurement_digest": "supplied_issuer_measurement_digest",
        "issuer_attestation_receipt_digest": "supplied_issuer_attestation_receipt_digest",
        "issuer_credential_issuance_digest": "supplied_issuer_credential_issuance_digest",
        **{name: "NULL" for name in authority.WRITER_CAPABILITY_TERMINAL_COLUMNS}, "status": "'issued'"})
    retained = {"capability_id": "rvi_capability_id", "capability_protocol": "'revocation-v4'",
        "capability_record_digest": "rvi_record_digest", "planner_transaction_id": "rvi_planner_id",
        "plan_protocol": "'revocation-v4'", "retained_record_digest": "rv_record_digest", "execution_envelope_id": "rvi_execution_id",
        "capability_digest": "rvi_capability_digest", "root_transition_digest": "rv_plan->'rootTransitionDigest'",
        "authority_snapshot_digest": "rv_snapshot_digest", "exact_request_bytes_digest": "execution_row.exact_request_bytes_digest",
        "exact_capability_base64url": "supplied_original_capability_base64url", "exact_capability_bytes_digest": "rvi_header->'envelopeDigest'",
        "exact_capability_byte_count": "pg_catalog.octet_length(rvi_envelope_bytes)", "signer_key_digest": "supplied_signer_key_digest",
        "witness_key_digest": "supplied_witness_key_digest", "exact_witness_request_base64url": "supplied_original_witness_request_base64url",
        "exact_witness_request_bytes_digest": "rvi_header->'witnessRequestBytesDigest'", "exact_witness_request_byte_count": "pg_catalog.octet_length(rvi_request_bytes)",
        "source_revision": _literal(authority.SOURCE_REVISION)}
    witness = {column: "rvi_receipt->" + _literal(name) for column, name in zip(_WITNESS_FIELDS,
        (None, "witnessIdentityDigest", "sequence", "headDigest", "predecessorHeadDigest", "predecessorReceiptDigest",
         "logPredecessorHeadDigest", "phase", "operation", "requestDigest", "capabilityId", "resultDigest", "fence", None, "issuedAtEpochNs")) if name is not None}
    witness.update({"witness_receipt_digest": "rvi_witness_digest", "receipt_json": "rvi_receipt_text"})
    inserts = "\n".join(f"""
        INSERT INTO {namespace}.{table} ({', '.join(fields)})
        SELECT {', '.join('candidate.' + field for field in fields)}
        FROM pg_catalog.jsonb_populate_record(NULL::{namespace}.{table}, {value}) AS candidate;
    """ for table, fields, value in (
        (authority.REVOCATION_RETAINED_CAPABILITY_TABLE, authority.REVOCATION_RETAINED_CAPABILITY_COLUMNS, "rvi_expected_retained"),
        ("policy_authority_writer_capabilities", _CAPABILITY_FIELDS, "rvi_expected_capability")))
    return f"""
        rvi_header := {_object(header)};
        {_wire(namespace, 'rvi_header', 'rvi_canonical', size=4194304, nodes=4096, depth=16)}
        rvi_record_digest := {_digest(namespace, capability.RECORD_SCHEMA, 'rvi_canonical')};
        IF rvi_record_digest IS DISTINCT FROM supplied_capability_record_digest
        THEN RAISE EXCEPTION 'revocation issuer retained capability commitment changed'; END IF;
        rvi_expected_capability := {_object(cap_values)};
        rvi_expected_retained := {_object(retained)};
        rvi_expected_witness := {_object(witness)};
        IF rvi_witness_present AND {_row('witness_row', _WITNESS_FIELDS)} IS DISTINCT FROM rvi_expected_witness
        THEN RAISE EXCEPTION 'revocation issuer existing witness is not exact'; END IF;
        IF rvi_capability_present THEN
            IF {_row('capability_row', _CAPABILITY_FIELDS)} IS DISTINCT FROM rvi_expected_capability
                OR {_row('retained_capability_row', authority.REVOCATION_RETAINED_CAPABILITY_COLUMNS)} IS DISTINCT FROM rvi_expected_retained
            THEN RAISE EXCEPTION 'revocation issuer retry changed original capability custody'; END IF;
        ELSE
            IF NOT rvi_witness_present THEN
                INSERT INTO {namespace}.policy_authority_external_witness_receipts ({', '.join(_WITNESS_FIELDS)})
                SELECT {', '.join('candidate.' + field for field in _WITNESS_FIELDS)} FROM pg_catalog.jsonb_populate_record(
                    NULL::{namespace}.policy_authority_external_witness_receipts, rvi_expected_witness) AS candidate;
            END IF;
            {inserts}
            UPDATE {namespace}.policy_authority_fence_heads
                SET fence = planner.fence, witness_sequence = (rvi_receipt->>'sequence')::bigint,
                    witness_head_digest = rvi_receipt->>'headDigest', updated_at_epoch_ns = planner.reserved_at_epoch_ns
                WHERE authority_scope = 'controlled-writer' AND fence = fence_row.fence
                    AND witness_sequence = fence_row.witness_sequence AND witness_head_digest = fence_row.witness_head_digest
                    AND fence < planner.fence AND witness_sequence < (rvi_receipt->>'sequence')::bigint
                    AND updated_at_epoch_ns <= planner.reserved_at_epoch_ns;
            GET DIAGNOSTICS rvi_count = ROW_COUNT;
            IF rvi_count <> 1 THEN RAISE EXCEPTION 'revocation issuer replay fence did not advance'; END IF;
        END IF;
        SELECT * INTO STRICT capability_row FROM {namespace}.policy_authority_writer_capabilities WHERE capability_id = rvi_capability_id;
        SELECT * INTO STRICT retained_capability_row FROM {namespace}.{authority.REVOCATION_RETAINED_CAPABILITY_TABLE} WHERE capability_id = rvi_capability_id;
        SELECT * INTO STRICT witness_row FROM {namespace}.policy_authority_external_witness_receipts WHERE witness_receipt_digest = rvi_witness_digest;
        IF {_row('capability_row', _CAPABILITY_FIELDS)} IS DISTINCT FROM rvi_expected_capability
            OR {_row('retained_capability_row', authority.REVOCATION_RETAINED_CAPABILITY_COLUMNS)} IS DISTINCT FROM rvi_expected_retained
            OR {_row('witness_row', _WITNESS_FIELDS)} IS DISTINCT FROM rvi_expected_witness
        THEN RAISE EXCEPTION 'revocation issuer inserted custody changed'; END IF;
        IF EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000000 >= planner.deadline_epoch_ns
        THEN RAISE EXCEPTION 'revocation issuer reservation deadline expired'; END IF;
        RETURN pg_catalog.jsonb_build_object('capabilityId', rvi_capability_id,
            'capabilityDigest', rvi_capability_digest, 'capabilityRecordDigest', rvi_record_digest);
    """


def revocation_capability_functions_sql(namespace: str, *, issuer_role: str, owner_role: str,
        issuer_measurement_digest: str, issuer_attestation_receipt_digest: str,
        issuer_credential_issuance_digest: str, issuer_tls_client_dn: str,
        issuer_tls_client_serial: str, issuer_tls_issuer_dn: str) -> str:
    """Render only the fixed load6/issue8 functions; install/grants are external.

    Installer must compare these fixed PG/timeouts to its canonical settings.
    Source-pinned identities are escaped data, never supplied SQL. The load
    result has eight exact row projections, not successful-verification DTOs.
    """
    if type(namespace) is not str:
        raise ValueError("revocation issuer namespace is not exact")
    _schema_name(namespace)
    for role in (issuer_role, owner_role):
        if type(role) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", role) is None:
            raise ValueError("revocation issuer role is not exact")
    if issuer_role == owner_role:
        raise ValueError("revocation issuer and owner roles must differ")
    for digest in (issuer_measurement_digest, issuer_attestation_receipt_digest, issuer_credential_issuance_digest):
        if type(digest) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise ValueError("revocation issuer pin is not exact")
    for value in (issuer_tls_client_dn, issuer_tls_issuer_dn):
        if type(value) is not str or not value or "\x00" in value or len(value.encode("utf-8")) > 4096:
            raise ValueError("revocation issuer TLS name is not bounded")
    if (type(issuer_tls_client_serial) is not str
            or re.fullmatch(r"[0-9A-Fa-f:]{1,256}", issuer_tls_client_serial) is None):
        raise ValueError("revocation issuer TLS serial is not exact")
    pins = (issuer_measurement_digest, issuer_attestation_receipt_digest, issuer_credential_issuance_digest)
    admission = f"""
        PERFORM pg_catalog.set_config('lock_timeout', {_literal(LOCK_TIMEOUT)}, TRUE);
        PERFORM pg_catalog.set_config('statement_timeout', {_literal(STATEMENT_TIMEOUT)}, TRUE);
        IF session_user IS DISTINCT FROM {_literal(issuer_role)} OR current_user IS DISTINCT FROM {_literal(owner_role)}
            OR pg_catalog.current_setting('server_version_num')::integer / 10000 <> {POSTGRES_MAJOR}
            OR pg_catalog.current_setting('transaction_isolation') IS DISTINCT FROM 'serializable'
            OR pg_catalog.current_setting('transaction_read_only') IS DISTINCT FROM 'off'
            OR pg_catalog.current_setting('transaction_deferrable') IS DISTINCT FROM 'off'
        THEN RAISE EXCEPTION 'revocation issuer session or transaction is not exact'; END IF;
        SELECT ssl, client_dn, client_serial::text, issuer_dn
            INTO STRICT rvi_tls_active, rvi_tls_dn, rvi_tls_serial, rvi_tls_issuer
            FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid();
        IF rvi_tls_active IS DISTINCT FROM TRUE OR rvi_tls_dn IS DISTINCT FROM {_literal(issuer_tls_client_dn)}
            OR rvi_tls_serial IS DISTINCT FROM {_literal(issuer_tls_client_serial)}
            OR rvi_tls_issuer IS DISTINCT FROM {_literal(issuer_tls_issuer_dn)}
            OR {' OR '.join(name + ' IS DISTINCT FROM ' + _literal(value) for name, value in zip(_ISSUER_ARGUMENTS, pins))}
        THEN RAISE EXCEPTION 'revocation issuer identity is not pinned'; END IF;
        rvi_issuer_identity := {namespace}.catchplate_policy_authority_domain_digest(
            'catchplate.policyAuthorityCapabilityIssuerSession/v1', session_user, rvi_tls_dn, rvi_tls_serial, rvi_tls_issuer,
            {', '.join(_literal(value) for value in pins)});
    """
    projections = {
        "planner": _row("planner", revocation_retention._PARENT_FIELDS),
        "retainedPlan": _row("rv_retained", authority.REVOCATION_RETAINED_COLUMNS),
        "execution": _row("execution_row", revocation_execution._FIELDS),
        "assertion": _row("assertion_row", authorization_records._ASSERTION_FIELDS),
        "projection": _row("projection_row", authorization_records._PROJECTION_FIELDS),
        "capability": "CASE WHEN rvi_capability_present THEN " + _row("capability_row", _CAPABILITY_FIELDS) + " ELSE NULL END",
        "retainedCapability": "CASE WHEN rvi_retained_present THEN " + _row("retained_capability_row", authority.REVOCATION_RETAINED_CAPABILITY_COLUMNS) + " ELSE NULL END",
        "witness": "CASE WHEN rvi_witness_present THEN " + _row("witness_row", _WITNESS_FIELDS) + " ELSE NULL END",
    }
    load_arguments = ("supplied_planner_transaction_id", "supplied_execution_envelope_id", "supplied_capability_id", *_ISSUER_ARGUMENTS)
    issue_arguments = ("supplied_original_capability_base64url", "supplied_original_witness_request_base64url",
        "supplied_capability_record_digest", "supplied_signer_key_digest", "supplied_witness_key_digest", *_ISSUER_ARGUMENTS)
    load_body = f"""
        {_require_digests(load_arguments[:3])}
        rvi_planner_id := supplied_planner_transaction_id;
        rvi_execution_id := supplied_execution_envelope_id;
        rvi_capability_id := supplied_capability_id;
        {_custody(namespace)}
        RETURN {_object(projections)};
    """
    issue_body = f"""
        {_require_digests(issue_arguments[2:5])}
        {_transport(namespace, issue_arguments[0], 'rvi_envelope', capability.MAX_CAPABILITY_BYTES)}
        {_transport(namespace, issue_arguments[1], 'rvi_request', capability.MAX_WITNESS_REQUEST_BYTES)}
        rvi_capability := rvi_envelope->'payload';
        IF NOT {_closed('rvi_envelope', capability.SIGNED_FIELDS)}
            OR NOT {_closed('rvi_capability', capability.PAYLOAD_FIELDS)}
            OR NOT {_closed("rvi_envelope->'signerIdentity'", ('sessionIdentityDigest', 'measurementDigest', 'attestationReceiptDigest'))}
            OR rvi_envelope->>'schema' IS DISTINCT FROM {_literal(capability.SIGNED_SCHEMA)}
            OR rvi_envelope->>'sourceRevision' IS DISTINCT FROM {_literal(authority.SOURCE_REVISION)}
        THEN RAISE EXCEPTION 'revocation issuer signed capability shape changed'; END IF;
        {_require_digests(tuple("rvi_envelope->'signerIdentity'->>" + _literal(name) for name in ('sessionIdentityDigest', 'measurementDigest', 'attestationReceiptDigest')))}
        rvi_planner_id := rvi_capability->>'plannerTransactionId';
        rvi_execution_id := rvi_capability->>'envelopeId';
        rvi_capability_id := rvi_capability->>'capabilityId';
        {_require_digests(('rvi_planner_id', 'rvi_execution_id', 'rvi_capability_id'))}
        {_custody(namespace)}
        {_witness(namespace)}
        {_expected(namespace)}
        {_storage(namespace)}
    """
    return "\n".join(textwrap.dedent(f"""
        CREATE OR REPLACE FUNCTION {namespace}.{name}(
            {', '.join(argument + ' text' for argument in arguments)})
        RETURNS pg_catalog.jsonb LANGUAGE plpgsql SECURITY DEFINER VOLATILE
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $catchplate_revocation_issuer$
        DECLARE
            {_declarations(namespace)}
        BEGIN
            {admission}
            {body}
        END;
        $catchplate_revocation_issuer$;
    """) for name, arguments, body in (
        (LOAD_FUNCTION, load_arguments, load_body), (ISSUE_FUNCTION, issue_arguments, issue_body)))
