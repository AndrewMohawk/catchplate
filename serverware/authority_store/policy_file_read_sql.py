"""Fixed current-policy read/lock purpose. No DML or runtime installation."""
from __future__ import annotations
import hashlib
import re

from serverware.authority_store import successor_execution_privileges as privileges

ROLE = "serverware_policy_file_materializer"
FUNCTION = "serverware_policy_file_current_lock"
CONTRACT = "serverware.policyFileCurrentLock/v1"
TABLES = tuple(sorted({"policy_high_water", "policy_publications", "policy_activation_preparations",
    "policy_activation_attempts", "policy_activation_finalizations", "policy_activation_publication_receipts",
    "policy_activation_approval_consumptions", "policy_activation_heads", "policy_canary_heads",
    "policy_activation_prepared_transitions", "policy_authority_audit_inclusion_receipts", "policy_candidate_artifacts",
    "policy_native_canary_ready", "policy_native_canary_heads", "policy_native_activation_preparations",
    "policy_native_activation_finalizations", "metadata_audit_outbox", "control_plane_approvals"}))


def privilege_check(*, namespace):
    if type(namespace) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", namespace) is None:
        raise ValueError("policy file namespace is not exact")
    # Same genuine zero-table/one-function effective privilege query; neither
    # a supplied relation inventory nor a new broad runtime role is accepted.
    return privileges.SUCCESSOR_EXECUTION_PRIVILEGE_SQL, (ROLE, namespace, [], FUNCTION)


def body(namespace):
    if type(namespace) is not str or re.fullmatch(r'"[a-z][a-z0-9_]{0,62}"', namespace) is None:
        raise ValueError("policy file namespace is not source quoted")
    tables = ", ".join(namespace + '."' + name + '"' for name in TABLES)
    roots = ", ".join("'" + name + "'" for name in TABLES)
    return f"""
DECLARE current_value jsonb; artifact_value jsonb; root_record record; root_count integer := 0;
BEGIN
    IF session_user::text <> '{ROLE}' OR current_setting('transaction_read_only') <> 'off'
       OR expected_artifact IS NULL OR expected_policy IS NULL
       OR expected_artifact !~ '^sha256:[0-9a-f]{{64}}$'
       OR expected_policy !~ '^sha256:[0-9a-f]{{64}}$' THEN
        RAISE EXCEPTION 'policy file read-lock purpose is not exact';
    END IF;
    -- Actual v9 executor takes this same row FOR UPDATE before all other
    -- authority locks. No advisory-lock substitution and no writer call while
    -- this independent connection retains its shared fence.
    PERFORM 1 FROM {namespace}.policy_authority_fence_heads
      WHERE authority_scope = 'controlled-writer' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'controlled writer fence is absent'; END IF;
    FOR root_record IN SELECT * FROM {namespace}.policy_authority_authenticated_table_roots
      WHERE table_name IN ({roots}) ORDER BY table_name COLLATE "C" FOR SHARE LOOP
        root_count := root_count + 1;
    END LOOP;
    IF root_count <> {len(TABLES)} THEN RAISE EXCEPTION 'current policy roots are incomplete'; END IF;
    -- Fixed table locks also exclude non-executor owner publication while the
    -- exact current originals are held. Their source order is deterministic.
    LOCK TABLE {tables} IN SHARE MODE;
    SELECT jsonb_build_object('policyId', h.policy_id, 'sequence', h.sequence,
        'rollbackEpoch', h.rollback_epoch, 'policyHash', h.policy_hash,
        'preparationDigest', p.preparation_digest, 'finalizationDigest', f.finalization_digest,
        'artifactEnvelopeSha256', a.artifact_envelope_digest), to_jsonb(a)
      INTO STRICT current_value, artifact_value
      FROM {namespace}.policy_high_water h
      JOIN {namespace}.policy_publications pub ON pub.scope = h.scope AND pub.policy_id = h.policy_id
        AND pub.sequence = h.sequence AND pub.rollback_epoch = h.rollback_epoch
        AND pub.policy_hash = h.policy_hash AND pub.status = 'committed'
      JOIN {namespace}.policy_activation_preparations p ON p.candidate_policy_hash = h.policy_hash
        AND p.candidate_policy_sequence = h.sequence AND p.candidate_rollback_epoch = h.rollback_epoch
      JOIN {namespace}.policy_activation_attempts attempt ON attempt.activation_attempt_id = p.activation_attempt_id
      JOIN {namespace}.policy_activation_finalizations f ON f.preparation_digest = p.preparation_digest
        AND f.activation_attempt_id = p.activation_attempt_id
      JOIN {namespace}.policy_activation_publication_receipts receipt ON receipt.activation_attempt_id = p.activation_attempt_id
        AND receipt.committed_policy_hash = h.policy_hash AND receipt.committed_policy_sequence = h.sequence
        AND receipt.committed_rollback_epoch = h.rollback_epoch AND receipt.publication_status = 'committed'
        AND receipt.publication_receipt_payload_digest = f.publication_receipt_payload_digest
      JOIN {namespace}.policy_activation_approval_consumptions consumed ON consumed.activation_attempt_id = p.activation_attempt_id
        AND consumed.approval_id = p.approval_id AND consumed.consumption_digest = p.approval_consumption_digest
      JOIN {namespace}.policy_activation_heads head ON head.activation_attempt_id = p.activation_attempt_id
        AND head.status = 'committed' AND head.unresolved_indeterminate = 0
      JOIN {namespace}.policy_canary_heads canary ON canary.canary_id = attempt.canary_id AND canary.status = 'active'
      JOIN {namespace}.policy_candidate_artifacts a ON a.policy_hash = h.policy_hash AND a.policy_id = h.policy_id
        AND a.policy_sequence = h.sequence AND a.rollback_epoch = h.rollback_epoch AND a.scope = 'active'
        AND a.artifact_envelope_digest = attempt.artifact_envelope_digest
      WHERE h.scope = 'active'
        AND (SELECT count(*) FROM {namespace}.policy_activation_prepared_transitions counted
             WHERE counted.preparation_digest = p.preparation_digest) = p.transition_count
        AND NOT EXISTS (SELECT 1 FROM {namespace}.policy_activation_prepared_transitions prepared
          LEFT JOIN {namespace}.policy_authority_audit_inclusion_receipts inclusion
            ON inclusion.transition_digest = prepared.transition_digest AND inclusion.outbox_id = prepared.outbox_id
            AND inclusion.outbox_event_digest = prepared.outbox_event_digest
          WHERE prepared.preparation_digest = p.preparation_digest AND inclusion.transition_digest IS NULL)
    UNION ALL
    SELECT jsonb_build_object('policyId', h.policy_id, 'sequence', h.sequence,
        'rollbackEpoch', h.rollback_epoch, 'policyHash', h.policy_hash,
        'preparationDigest', p.prepared_sha256, 'finalizationDigest', f.finalization_digest,
        'artifactEnvelopeSha256', a.artifact_envelope_digest), to_jsonb(a)
      FROM {namespace}.policy_high_water h
      JOIN {namespace}.policy_publications pub ON pub.scope = h.scope AND pub.policy_id = h.policy_id
        AND pub.sequence = h.sequence AND pub.rollback_epoch = h.rollback_epoch
        AND pub.policy_hash = h.policy_hash AND pub.status = 'committed'
      JOIN {namespace}.policy_native_activation_finalizations f ON f.policy_id = h.policy_id AND f.policy_hash = h.policy_hash
        AND f.policy_sequence = h.sequence AND f.rollback_epoch = h.rollback_epoch
      JOIN {namespace}.policy_native_activation_preparations p ON p.canary_id = f.canary_id
        AND p.activation_id = f.activation_id AND p.prepared_sha256 = f.prepared_sha256 AND p.publication_sha256 = f.publication_sha256
      JOIN {namespace}.policy_native_canary_ready ready ON ready.canary_id = p.canary_id
      JOIN {namespace}.policy_native_canary_heads head ON head.canary_id = p.canary_id
        AND head.source_profile = 'native-policy-activation/v1' AND head.status = 'active'
        AND head.head_revision = ready.ready_revision + 1 AND head.head_state_digest = f.finalization_digest
        AND head.ready_state_digest = ready.ready_state_digest
      JOIN {namespace}.policy_canary_heads predecessor ON predecessor.canary_id = p.canary_id AND predecessor.status = 'sealing'
        AND predecessor.head_revision = head.predecessor_revision AND predecessor.head_state_digest = head.predecessor_state_digest
      JOIN {namespace}.control_plane_approvals approval ON approval.id = p.approval_id
        AND approval.action = 'policy.native.activate' AND approval.resource_id = 'native-policy-activation'
        AND approval.status = 'consumed' AND approval.requester_id = p.requester_id AND approval.consumed_by = p.requester_id
        AND approval.approved_by IS NOT NULL AND approval.approved_by <> approval.requester_id
      JOIN {namespace}.policy_candidate_artifacts a ON a.artifact_envelope_digest = f.artifact_envelope_digest
        AND a.policy_hash = h.policy_hash AND a.policy_id = h.policy_id AND a.policy_sequence = h.sequence
        AND a.rollback_epoch = h.rollback_epoch AND a.scope = 'active'
      WHERE h.scope = 'active'
        AND p.prepared_sha256 = 'sha256:' || encode(sha256(convert_to(p.prepared_original, 'UTF8')), 'hex')
        AND p.publication_sha256 = 'sha256:' || encode(sha256(convert_to(p.publication_original, 'UTF8')), 'hex')
        AND f.finalization_digest = 'sha256:' || encode(sha256(convert_to(f.finalization_original, 'UTF8')), 'hex')
        AND p.prepared_original::jsonb->>'readyOriginal' = ready.ready_original
        AND p.prepared_original::jsonb->>'readinessOriginal' = ready.readiness_result_original
        AND (p.prepared_original::jsonb->>'approvalOriginal')::jsonb = to_jsonb(approval)
        AND p.publication_original::jsonb->'payload'->>'preparedSha256' = p.prepared_sha256
        AND p.publication_original::jsonb->'payload'->>'requestSha256' = p.publication_request_sha256
        AND p.publication_original::jsonb->'payload'->'publicationAfter'->>'policySha256' = h.policy_hash
        AND (p.publication_original::jsonb->'payload'->'publicationAfter'->>'policySequence')::bigint = h.sequence
        AND (p.publication_original::jsonb->'payload'->'publicationAfter'->>'rollbackEpoch')::bigint = h.rollback_epoch
        AND pub.previous_policy_hash = p.prepared_original::jsonb->'publicationBefore'->>'policySha256'
        AND jsonb_array_length(f.audit_originals_json::jsonb) = 4
        AND (SELECT count(DISTINCT item->>'id') FROM jsonb_array_elements(f.audit_originals_json::jsonb) item) = 4
        AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(f.audit_originals_json::jsonb) item
          LEFT JOIN {namespace}.metadata_audit_outbox actual ON actual.id = item->>'id'
          WHERE actual.id IS NULL OR actual.status <> 'audited' OR actual.audited_at IS NULL
            OR actual.audit_event_hash IS NULL OR to_jsonb(actual) IS DISTINCT FROM item);
    IF current_value->>'policyHash' <> expected_policy
       OR current_value->>'artifactEnvelopeSha256' <> expected_artifact
       OR octet_length(artifact_value::text) > 16777216 THEN
        RAISE EXCEPTION 'policy file original is not the exact current committed artifact';
    END IF;
    RETURN jsonb_build_object('schema', '{CONTRACT}', 'current', current_value, 'artifact', artifact_value,
        'backendPid', pg_backend_pid(), 'transactionId', txid_current()::text);
END
"""


def functions_sql(namespace, *, owner_role):
    if type(owner_role) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", owner_role) is None or owner_role == ROLE:
        raise ValueError("policy file function owner is not exact")
    source = body(namespace)
    return f'''CREATE OR REPLACE FUNCTION {namespace}."{FUNCTION}"(expected_artifact text, expected_policy text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path TO pg_catalog, {namespace}, pg_temp AS $policy_file${source}$policy_file$;
ALTER FUNCTION {namespace}."{FUNCTION}"(text, text) OWNER TO "{owner_role}";
REVOKE ALL ON FUNCTION {namespace}."{FUNCTION}"(text, text) FROM PUBLIC;'''


SQL_DIGEST = "sha256:" + hashlib.sha256(body('"serverware_metadata"').encode("utf-8")).hexdigest()
