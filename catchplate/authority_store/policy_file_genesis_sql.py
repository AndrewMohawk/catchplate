"""Separate fixed genesis read-lock purpose; never activates or initializes state."""
from __future__ import annotations

import hashlib
import re

from catchplate.authority_store import successor_execution_privileges as privileges

ROLE = "catchplate_policy_file_genesis_materializer"
FUNCTION = "catchplate_policy_file_genesis_lock"
CONTRACT = "catchplate.policyFileGenesisLock/v1"
TABLES = tuple(sorted({"policy_high_water", "policy_publications",
    "policy_authority_genesis_preparations", "policy_authority_genesis_finalizations",
    "policy_authority_evidence_verifications", "policy_authority_transition_audits",
    "policy_authority_audit_inclusion_receipts", "policy_authority_trusted_keys"}))


def privilege_check(*, namespace):
    if type(namespace) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", namespace) is None:
        raise ValueError("genesis namespace is not exact")
    return privileges.SUCCESSOR_EXECUTION_PRIVILEGE_SQL, (ROLE, namespace, [], FUNCTION)


def body(namespace):
    if type(namespace) is not str or re.fullmatch(r'"[a-z][a-z0-9_]{0,62}"', namespace) is None:
        raise ValueError("genesis namespace is not source quoted")
    tables = ", ".join(namespace + '."' + name + '"' for name in TABLES)
    roots = ", ".join("'" + name + "'" for name in TABLES)
    return f"""
DECLARE current_value jsonb; originals_value jsonb; root_record record; root_count integer := 0;
BEGIN
    IF session_user::text <> '{ROLE}' OR current_setting('transaction_read_only') <> 'off'
       OR expected_preparation IS NULL OR expected_finalization IS NULL
       OR expected_preparation !~ '^sha256:[0-9a-f]{{64}}$'
       OR expected_finalization !~ '^sha256:[0-9a-f]{{64}}$' THEN
        RAISE EXCEPTION 'genesis file read-lock purpose is not exact';
    END IF;
    PERFORM 1 FROM {namespace}.policy_authority_fence_heads
      WHERE authority_scope = 'controlled-writer' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'controlled writer fence is absent'; END IF;
    FOR root_record IN SELECT * FROM {namespace}.policy_authority_authenticated_table_roots
      WHERE table_name IN ({roots}) ORDER BY table_name COLLATE "C" FOR SHARE LOOP
        root_count := root_count + 1;
    END LOOP;
    IF root_count <> {len(TABLES)} THEN RAISE EXCEPTION 'genesis roots are incomplete'; END IF;
    LOCK TABLE {tables} IN SHARE MODE;
    -- Positive finalized, signed and audit-included genesis. Neither missing
    -- files nor an empty relation is used as a substitute for this chain.
    SELECT jsonb_build_object('policyId', h.policy_id, 'sequence', h.sequence,
        'rollbackEpoch', h.rollback_epoch, 'policyHash', h.policy_hash,
        'genesisPreparationDigest', p.genesis_preparation_digest,
        'genesisFinalizationDigest', f.finalization_digest),
      jsonb_build_object('preparation', to_jsonb(p), 'finalization', to_jsonb(f),
        'signatureEvidence', to_jsonb(v), 'transition', to_jsonb(t),
        'inclusion', to_jsonb(i), 'inclusionEvidence', to_jsonb(iv))
      INTO STRICT current_value, originals_value
      FROM {namespace}.policy_high_water h
      JOIN {namespace}.policy_publications pub ON pub.scope = h.scope AND pub.policy_id = h.policy_id
        AND pub.sequence = h.sequence AND pub.rollback_epoch = h.rollback_epoch
        AND pub.policy_hash = h.policy_hash AND pub.status = 'committed'
        AND pub.previous_policy_hash IS NULL
      JOIN {namespace}.policy_authority_genesis_preparations p ON p.policy_id = h.policy_id
        AND p.policy_sequence = h.sequence AND p.rollback_epoch = h.rollback_epoch AND p.policy_hash = h.policy_hash
      JOIN {namespace}.policy_authority_genesis_finalizations f
        ON f.genesis_preparation_digest = p.genesis_preparation_digest AND f.policy_id = p.policy_id
        AND f.policy_sequence = p.policy_sequence AND f.rollback_epoch = p.rollback_epoch
        AND f.policy_hash = p.policy_hash AND f.high_water_digest = p.high_water_digest
        AND f.genesis_transition_digest = p.genesis_transition_digest
        AND f.finalized_at_epoch_ns >= p.prepared_at_epoch_ns
        AND f.finalized_at_epoch_ns < p.expires_at_epoch_ns
      JOIN {namespace}.policy_authority_evidence_verifications v
        ON v.verification_receipt_digest = p.verification_receipt_digest
        AND v.evidence_kind = 'authority_genesis' AND p.evidence_kind = v.evidence_kind
        AND v.signature_domain = 'catchplate.policyAuthorityGenesis/v1'
        AND v.signing_key_id = p.signing_key_id AND v.signature = p.signature
        AND v.signature_digest = p.signature_digest AND v.record_binding_digest = p.record_binding_digest
        AND v.envelope_digest = p.genesis_envelope_digest AND v.payload_digest = p.genesis_payload_digest
      JOIN {namespace}.policy_authority_trusted_keys k
        ON k.evidence_kind = v.evidence_kind AND k.key_revision = v.trusted_key_revision
        AND k.signing_key_id = v.signing_key_id AND k.public_key_digest = v.public_key_digest
        AND k.signature_domain = v.signature_domain
      JOIN {namespace}.policy_authority_transition_audits t
        ON t.transition_digest = p.genesis_transition_digest
        AND t.event_type = 'policy.authority.genesis.prepared' AND t.entity_kind = 'activation_genesis'
        AND t.entity_id = p.policy_hash AND t.entity_revision = 1
        AND t.state_digest = p.genesis_preparation_digest AND t.previous_state_digest IS NULL
      JOIN {namespace}.policy_authority_audit_inclusion_receipts i
        ON i.inclusion_receipt_envelope_digest = f.inclusion_receipt_envelope_digest
        AND i.transition_digest = t.transition_digest AND i.outbox_id = t.outbox_id
        AND i.outbox_event_digest = t.outbox_event_digest AND i.audit_ledger_namespace = 'catchplate.policy-authority'
      JOIN {namespace}.policy_authority_evidence_verifications iv
        ON iv.verification_receipt_digest = i.verification_receipt_digest
        AND iv.evidence_kind = 'audit_inclusion_receipt' AND i.evidence_kind = iv.evidence_kind
        AND iv.signature_domain = 'catchplate.policyAuthorityAuditInclusion/v1'
        AND iv.signing_key_id = i.signing_key_id AND iv.signature = i.signature
        AND iv.signature_digest = i.signature_digest AND iv.record_binding_digest = i.record_binding_digest
        AND iv.envelope_digest = i.inclusion_receipt_envelope_digest
        AND iv.payload_digest = i.inclusion_receipt_payload_digest
      JOIN {namespace}.policy_authority_trusted_keys ik
        ON ik.evidence_kind = iv.evidence_kind AND ik.key_revision = iv.trusted_key_revision
        AND ik.signing_key_id = iv.signing_key_id AND ik.public_key_digest = iv.public_key_digest
        AND ik.signature_domain = iv.signature_domain
      WHERE h.scope = 'active' AND p.genesis_preparation_digest = expected_preparation
        AND f.finalization_digest = expected_finalization;
    IF octet_length(originals_value::text) > 16777216 THEN
        RAISE EXCEPTION 'genesis originals exceed the fixed bound';
    END IF;
    RETURN jsonb_build_object('schema', '{CONTRACT}', 'current', current_value, 'originals', originals_value,
        'backendPid', pg_backend_pid(), 'transactionId', txid_current()::text);
END
"""


def functions_sql(namespace, *, owner_role):
    if type(owner_role) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", owner_role) is None or owner_role == ROLE:
        raise ValueError("genesis function owner is not exact")
    source = body(namespace)
    return f'''CREATE OR REPLACE FUNCTION {namespace}."{FUNCTION}"(expected_preparation text, expected_finalization text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path TO pg_catalog, {namespace}, pg_temp AS $policy_genesis${source}$policy_genesis$;
ALTER FUNCTION {namespace}."{FUNCTION}"(text, text) OWNER TO "{owner_role}";
REVOKE ALL ON FUNCTION {namespace}."{FUNCTION}"(text, text) FROM PUBLIC;'''


SQL_DIGEST = "sha256:" + hashlib.sha256(body('"catchplate_metadata"').encode("utf-8")).hexdigest()
