"""Framework-only currentness veto for the planner's complete JIT voter set.

This neither discovers voters for the kernel nor counts approvals. The selected
bounded partition must equal the actual locked partition, including the empty
first-decision case. Historical votes then need their original committed writer
and WebAuthn evidence plus current credential, role and trust eligibility.
The caller retains its existing SERIALIZABLE, fence, root and trust locks. All
failures abort that same transaction, before history retention/business writes.
"""
from __future__ import annotations

from catchplate.authority_store.mutation_sql import _schema_name
from catchplate.authority_store.webauthn_receipt_binding import (
    _exact_keys, receipt_evidence_binding_sql,
)
from catchplate.authority_store.webauthn_receipt_history import (
    assert_webauthn_receipt_history_sql,
)
from catchplate.authority_store.webauthn_trust_sql import webauthn_credential_policy_sql
from catchplate.authority_store.webauthn_challenge_sql import challenge_original_sql


def assert_prior_jit_decisions_sql(namespace: str) -> str:
    """Render a nested block using only fixed, already-admitted executor aliases.

    Required outer rows: capability, planner, trust_publication; scalars:
    computed_trust_high_water_digest and now_epoch_ns. No SQL inputs other than
    the checked installation namespace, and no standalone authorization API.
    """
    _schema_name(namespace)
    return f"""
        IF capability.operation = 'jit.decide' THEN
            DECLARE
                jit_approval pg_catalog.jsonb;
                jit_new_decision pg_catalog.jsonb;
                jit_policy pg_catalog.jsonb;
                jit_credential_policy pg_catalog.jsonb;
                jit_selected pg_catalog.jsonb;
                jit_actual pg_catalog.jsonb;
                jit_decision pg_catalog.jsonb;
                jit_authority_policy_digest text;
                jit_count bigint;
                jit_now numeric;
                prior_capability record;
                prior_writer record;
                prior_credential record;
                prior_challenge record;
                prior_role record;
                prior_roles pg_catalog.jsonb;
            BEGIN
                SELECT pg_catalog.count(*) INTO jit_count
                FROM pg_catalog.jsonb_array_elements(planner.selected_business_rows_json::pg_catalog.jsonb) AS item(value)
                WHERE item.value->>'table' = 'approval_requests';
                IF jit_count <> 1 THEN
                    RAISE EXCEPTION 'authority JIT approval selection is not exact';
                END IF;
                SELECT item.value->'row' INTO STRICT jit_approval
                FROM pg_catalog.jsonb_array_elements(planner.selected_business_rows_json::pg_catalog.jsonb) AS item(value)
                WHERE item.value->>'table' = 'approval_requests'
                  AND item.value->'present' = 'true'::pg_catalog.jsonb;
                SELECT pg_catalog.count(*) INTO jit_count
                FROM pg_catalog.jsonb_array_elements(planner.mutation_plan_json::pg_catalog.jsonb) AS item(value)
                WHERE item.value->>'table' = 'approval_request_decisions';
                IF jit_count <> 1 THEN
                    RAISE EXCEPTION 'authority JIT new decision is not exact';
                END IF;
                SELECT item.value->'row' INTO STRICT jit_new_decision
                FROM pg_catalog.jsonb_array_elements(planner.mutation_plan_json::pg_catalog.jsonb) AS item(value)
                WHERE item.value->>'table' = 'approval_request_decisions'
                  AND item.value->>'operation' = 'INSERT';
                IF (jit_new_decision->'approval_request_id' = jit_approval->'id'
                    AND jit_new_decision->>'authority_capability_id' = capability.capability_id
                    AND jit_new_decision->>'authority_request_digest' = capability.request_digest
                    AND jit_new_decision->>'verified_assertion_receipt_digest' = capability.webauthn_receipt_digest
                    AND jit_new_decision->>'approver_policy_digest' = jit_approval->>'approver_policy_digest'
                    AND jit_new_decision->>'decision' = 'approved'
                ) IS NOT TRUE THEN
                    RAISE EXCEPTION 'authority JIT new decision binding changed';
                END IF;
                jit_policy := (jit_approval->>'approver_policy_json')::pg_catalog.jsonb;
                jit_credential_policy := jit_policy->'credentialPolicy';
                IF ({_exact_keys("(jit_approval->>'approver_policy_json')::pg_catalog.json", ('schema', 'requiredRoles', 'roleMatch', 'allowedApproverIds', 'allowAnyApproverId', 'requireWebAuthn', 'threshold', 'credentialPolicy'))}
                    AND jit_approval->>'approver_policy_json' =
                        {namespace}.catchplate_policy_authority_wire_json(jit_policy)
                    AND jit_approval->>'approver_policy_digest' =
                        {namespace}.catchplate_policy_authority_domain_digest(
                            'catchplate.jitApproverPolicy/v1', jit_approval->>'approver_policy_json')
                    AND jit_policy->>'schema' = 'catchplate.jitApproverPolicy/v1'
                    AND jit_policy->>'roleMatch' = 'any'
                    AND jit_policy->'requireWebAuthn' = 'true'::pg_catalog.jsonb
                    AND pg_catalog.jsonb_typeof(jit_policy->'requiredRoles') = 'array'
                    AND pg_catalog.jsonb_typeof(jit_policy->'allowedApproverIds') = 'array'
                    AND jit_policy->'allowAnyApproverId' IN ('true'::pg_catalog.jsonb, 'false'::pg_catalog.jsonb)
                    AND pg_catalog.jsonb_typeof(jit_policy->'threshold') = 'number'
                    AND (jit_policy->>'threshold')::numeric BETWEEN 1 AND 16
                    AND (jit_policy->>'threshold')::numeric = pg_catalog.trunc((jit_policy->>'threshold')::numeric)
                    AND {_exact_keys("(jit_approval->>'approver_policy_json')::pg_catalog.json->'credentialPolicy'", ('allowedCredentialRecordIds', 'allowedAuthenticatorClasses', 'allowedAaguids', 'requireAttestationTrusted', 'requiredTrustBundleDigest', 'minimumTrustBundleSequence', 'rpId', 'origins', 'requireUserPresence', 'requireUserVerification', 'counterPolicy', 'maxAssertionAgeSeconds'))}
                    AND pg_catalog.jsonb_typeof(jit_credential_policy->'allowedCredentialRecordIds') = 'array'
                    AND pg_catalog.jsonb_typeof(jit_credential_policy->'allowedAuthenticatorClasses') = 'array'
                    AND pg_catalog.jsonb_typeof(jit_credential_policy->'allowedAaguids') = 'array'
                    AND jit_credential_policy->'requireAttestationTrusted' IN ('true'::pg_catalog.jsonb, 'false'::pg_catalog.jsonb)
                    AND jit_credential_policy->'requireUserPresence' = 'true'::pg_catalog.jsonb
                    AND jit_credential_policy->'requireUserVerification' = 'true'::pg_catalog.jsonb
                    AND jit_credential_policy->>'counterPolicy' IN ('strict', 'strict-or-zero')
                    AND pg_catalog.jsonb_typeof(jit_credential_policy->'maxAssertionAgeSeconds') = 'number'
                    AND (jit_credential_policy->>'maxAssertionAgeSeconds')::numeric BETWEEN 1 AND 30
                    AND (jit_credential_policy->>'maxAssertionAgeSeconds')::numeric =
                        pg_catalog.trunc((jit_credential_policy->>'maxAssertionAgeSeconds')::numeric)
                ) IS NOT TRUE THEN
                    RAISE EXCEPTION 'authority JIT stored policy changed';
                END IF;
                jit_authority_policy_digest := {namespace}.catchplate_policy_authority_domain_digest(
                    'catchplate.authorityApproverPolicyBinding/v1',
                    {namespace}.catchplate_policy_authority_wire_json(pg_catalog.jsonb_build_object(
                        'schema', 'catchplate.authorityApproverPolicyBinding/v1',
                        'requiredApproverRoles', jit_policy->'requiredRoles',
                        'allowedApproverIds', jit_policy->'allowedApproverIds',
                        'allowAnyApproverId', jit_policy->'allowAnyApproverId',
                        'requireWebAuthn', jit_policy->'requireWebAuthn',
                        'threshold', jit_policy->'threshold',
                        'credentialPolicy', jit_credential_policy)));
                IF capability.approver_policy_digest IS DISTINCT FROM jit_authority_policy_digest THEN
                    RAISE EXCEPTION 'authority JIT capability policy changed';
                END IF;

                SELECT COALESCE(pg_catalog.jsonb_agg(item.value->'row' ORDER BY item.value->'row'->>'approver_id' COLLATE "C"), '[]'::pg_catalog.jsonb)
                INTO jit_selected
                FROM pg_catalog.jsonb_array_elements(planner.selected_business_rows_json::pg_catalog.jsonb) AS item(value)
                WHERE item.value->>'table' = 'approval_request_decisions'
                  AND item.value->'present' = 'true'::pg_catalog.jsonb;
                -- The seventeenth row is a bounded overflow witness. Equality
                -- cannot turn an omitted/foreign vote into a selected voter.
                SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(actual) ORDER BY actual.approver_id COLLATE "C"), '[]'::pg_catalog.jsonb)
                INTO jit_actual
                FROM (SELECT decision.* FROM {namespace}.approval_request_decisions AS decision
                      WHERE decision.approval_request_id = jit_approval->>'id'
                      ORDER BY decision.approver_id COLLATE "C" LIMIT 17 FOR UPDATE) AS actual;
                IF pg_catalog.jsonb_array_length(jit_selected) > 16
                    OR jit_actual IS DISTINCT FROM jit_selected
                    OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(jit_selected) AS vote(value)
                        WHERE vote.value->'approver_id' = jit_new_decision->'approver_id')
                THEN
                    RAISE EXCEPTION 'authority JIT prior voter partition changed';
                END IF;
                jit_now := pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000000);
                IF jit_now < now_epoch_ns OR jit_now >= capability.deadline_epoch_ns THEN
                    RAISE EXCEPTION 'authority JIT prior voter clock is invalid';
                END IF;
                FOR jit_decision IN SELECT value FROM pg_catalog.jsonb_array_elements(jit_selected)
                LOOP
                    IF (jit_decision->'approval_request_id' = jit_approval->'id'
                        AND jit_decision->'approver_policy_digest' = jit_approval->'approver_policy_digest'
                        AND jit_decision->>'decision' = 'approved'
                        AND (jit_policy->'allowAnyApproverId' = 'true'::pg_catalog.jsonb
                            OR jit_policy->'allowedApproverIds' @> pg_catalog.jsonb_build_array(jit_decision->'approver_id'))
                    ) IS NOT TRUE THEN
                        RAISE EXCEPTION 'authority JIT prior approver is ineligible';
                    END IF;
                    SELECT * INTO STRICT prior_capability
                    FROM {namespace}.policy_authority_writer_capabilities
                    WHERE capability_id = jit_decision->>'authority_capability_id' FOR UPDATE;
                    SELECT * INTO STRICT prior_writer
                    FROM {namespace}.policy_authority_writer_receipts
                    WHERE commit_receipt_digest = prior_capability.commit_receipt_digest FOR UPDATE;
                    IF (prior_capability.operation = 'jit.decide'
                        AND prior_capability.handler_name = 'approve_request'
                        AND prior_capability.status IN ('committed', 'reconciled')
                        AND prior_capability.request_digest = jit_decision->>'authority_request_digest'
                        AND prior_capability.webauthn_receipt_digest = jit_decision->>'verified_assertion_receipt_digest'
                        AND prior_capability.approver_policy_digest = jit_authority_policy_digest
                        AND prior_capability.webauthn_trust_high_water_digest = computed_trust_high_water_digest
                        AND prior_writer.capability_id = prior_capability.capability_id
                        AND prior_writer.envelope_id = prior_capability.envelope_id
                        AND prior_writer.operation = prior_capability.operation
                        AND prior_writer.handler_name = prior_capability.handler_name
                        AND prior_writer.request_digest = prior_capability.request_digest
                        AND prior_writer.result_digest = prior_capability.result_digest
                        AND prior_writer.operation_manifest_digest = prior_capability.operation_manifest_digest
                        AND prior_writer.query_manifest_digest = prior_capability.query_manifest_digest
                        AND prior_writer.witness_reservation_digest = prior_capability.witness_reservation_digest
                        AND prior_writer.witness_sequence = prior_capability.witness_sequence
                        AND prior_writer.deadline_monotonic_ns = prior_capability.deadline_monotonic_ns
                        AND prior_writer.fence = prior_capability.fence
                        AND prior_writer.committed_at_epoch_ns = prior_capability.committed_at_epoch_ns
                        AND prior_capability.commit_receipt_digest = {namespace}.catchplate_policy_authority_domain_digest(
                            'catchplate.policyAuthorityWriterCommitReceipt/v2',
                            {namespace}.catchplate_policy_authority_wire_json(pg_catalog.jsonb_build_object(
                                'schema', 'catchplate.policyAuthorityWriterCommitReceipt/v2',
                                'capabilityId', prior_capability.capability_id,
                                'envelopeId', prior_capability.envelope_id,
                                'plannerTransactionId', prior_capability.planner_transaction_id,
                                'authorizationProjectionDigest', prior_capability.authorization_projection_digest,
                                'operation', prior_capability.operation,
                                'handlerName', prior_capability.handler_name,
                                'requestDigest', prior_capability.request_digest,
                                'resultDigest', prior_writer.result_digest,
                                'authorityRootSetBeforeDigest', prior_writer.authority_root_set_before_digest,
                                'authorityRootSetAfterDigest', prior_writer.authority_root_set_after_digest,
                                'authoritySnapshotDigest', prior_capability.authority_snapshot_digest,
                                'operationManifestDigest', prior_capability.operation_manifest_digest,
                                'queryManifestDigest', prior_capability.query_manifest_digest,
                                'witnessReservationDigest', prior_capability.witness_reservation_digest,
                                'witnessSequence', prior_capability.witness_sequence,
                                'deadlineMonotonicNs', prior_capability.deadline_monotonic_ns,
                                'fence', prior_capability.fence,
                                'committedAtEpochNs', prior_capability.committed_at_epoch_ns,
                                'sourceRevision', prior_writer.source_revision)))
                        AND prior_writer.result_json = {namespace}.catchplate_policy_authority_wire_json(prior_writer.result_json::pg_catalog.jsonb)
                        AND prior_writer.result_digest = {namespace}.catchplate_policy_authority_domain_digest(
                            'catchplate.policyAuthorityControlledWriterResult/v2', prior_writer.result_json)
                    ) IS NOT TRUE THEN
                        RAISE EXCEPTION 'authority JIT prior writer commitment changed';
                    END IF;
                    DECLARE
                        capability record;
                        evidence record;
                        assertion_evidence record;
                    BEGIN
                        -- Shadow only the fixed alias used by the unchanged
                        -- production history and three-domain binding helpers.
                        capability := prior_capability;
                        {assert_webauthn_receipt_history_sql(namespace)}
                        SELECT * INTO STRICT evidence
                        FROM {namespace}.policy_authority_webauthn_assertion_evidence
                        WHERE capability_id = prior_capability.capability_id FOR UPDATE;
                        assertion_evidence := evidence;
                        IF (evidence.operation = capability.operation
                            AND evidence.operation_id = capability.operation_id
                            AND evidence.request_digest = capability.request_digest
                            AND evidence.capability_id = capability.capability_id
                            AND {receipt_evidence_binding_sql(namespace)}
                            AND evidence.trust_high_water_digest = computed_trust_high_water_digest
                            AND evidence.metadata_publication_sequence = trust_publication.sequence
                            AND evidence.rp_id = jit_credential_policy->>'rpId'
                            AND jit_credential_policy->'origins' = pg_catalog.jsonb_build_array(evidence.origin)
                            AND (evidence.flags & 5) = 5
                            AND evidence.counter > evidence.prior_counter
                            AND jit_now >= evidence.verified_at_epoch_ns
                            AND jit_now - evidence.verified_at_epoch_ns <=
                                (jit_credential_policy->>'maxAssertionAgeSeconds')::numeric * 1000000000
                        ) IS NOT TRUE THEN
                            RAISE EXCEPTION 'authority JIT prior assertion is not current';
                        END IF;
                        SELECT * INTO STRICT prior_credential FROM {namespace}.webauthn_credentials
                        WHERE id = evidence.credential_record_id FOR UPDATE;
                        SELECT * INTO STRICT prior_challenge FROM {namespace}.webauthn_challenges
                        WHERE id = evidence.challenge_id FOR UPDATE;
                        IF (prior_credential.credential_id = evidence.credential_id
                            AND prior_credential.user_id = jit_decision->>'approver_id'
                            AND prior_credential.revoked_at IS NULL
                            AND prior_credential.sign_count >= evidence.counter
                            AND prior_credential.attestation_trust_bundle_digest = trust_publication.bundle_digest
                            AND prior_credential.attestation_trust_bundle_sequence = trust_publication.sequence
                            AND prior_challenge.user_id = jit_decision->>'approver_id'
                            AND prior_challenge.challenge_type = 'policy_authority'
                            AND prior_challenge.scope_key = capability.operation_id
                            AND prior_challenge.used_at IS NOT NULL
                            AND capability.webauthn_receipt_json::pg_catalog.jsonb->>'challengeRowDigest' =
                                {namespace}.catchplate_policy_authority_domain_digest(
                                    'catchplate.policyAuthorityWebAuthnChallengeRow/v1',
                                    {namespace}.catchplate_policy_authority_wire_json(
                                        {challenge_original_sql(historical=True)}))
                            AND NOT (trust_publication.withdrawn_credential_ids_json::pg_catalog.jsonb
                                ?| ARRAY[prior_credential.id, prior_credential.credential_id])
                            AND jit_credential_policy->'allowedAuthenticatorClasses' @> pg_catalog.jsonb_build_array(prior_credential.authenticator_class)
                            AND (jit_credential_policy->'allowedCredentialRecordIds' = '[]'::pg_catalog.jsonb
                                OR jit_credential_policy->'allowedCredentialRecordIds' @> pg_catalog.jsonb_build_array(prior_credential.id))
                            AND (jit_credential_policy->'allowedAaguids' = '[]'::pg_catalog.jsonb
                                OR jit_credential_policy->'allowedAaguids' @> pg_catalog.jsonb_build_array(COALESCE(prior_credential.aaguid, '')))
                            AND (jit_credential_policy->'requireAttestationTrusted' = 'false'::pg_catalog.jsonb OR prior_credential.attestation_trusted = 1)
                            AND (jit_credential_policy->'requiredTrustBundleDigest' = 'null'::pg_catalog.jsonb
                                OR jit_credential_policy->>'requiredTrustBundleDigest' = prior_credential.attestation_trust_bundle_digest)
                            AND (jit_credential_policy->'minimumTrustBundleSequence' = 'null'::pg_catalog.jsonb
                                OR prior_credential.attestation_trust_bundle_sequence >= (jit_credential_policy->>'minimumTrustBundleSequence')::bigint)
                            AND evidence.credential_policy_digest = (
                                SELECT {namespace}.catchplate_policy_authority_domain_digest(
                                    'catchplate.policyAuthorityCredentialPolicy/v1',
                                    {namespace}.catchplate_policy_authority_wire_json({webauthn_credential_policy_sql()}))
                                FROM (SELECT pg_catalog.jsonb_build_object('expectedRow', pg_catalog.to_jsonb(prior_credential)) AS value) AS credential_mutation)
                        ) IS NOT TRUE THEN
                            RAISE EXCEPTION 'authority JIT prior credential or challenge changed';
                        END IF;
                    END;
                    IF pg_catalog.jsonb_array_length(jit_policy->'requiredRoles') > 0 THEN
                        SELECT * INTO STRICT prior_role FROM {namespace}.rbac_role_bindings
                        WHERE subject_id = jit_decision->>'approver_id' FOR UPDATE;
                        prior_roles := prior_role.roles_json::pg_catalog.jsonb;
                        IF prior_role.roles_json IS DISTINCT FROM {namespace}.catchplate_policy_authority_wire_json(prior_roles) THEN
                            RAISE EXCEPTION 'authority JIT prior roles are not canonical';
                        END IF;
                        IF pg_catalog.jsonb_typeof(prior_roles) = 'object' THEN
                            prior_roles := prior_roles->'roles';
                        END IF;
                        IF (prior_role.status = 'active'
                            AND pg_catalog.jsonb_typeof(prior_roles) = 'array'
                            AND EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(jit_policy->'requiredRoles') AS role(value)
                                WHERE prior_roles @> pg_catalog.jsonb_build_array(role.value))
                        ) IS NOT TRUE THEN
                            RAISE EXCEPTION 'authority JIT prior roles are no longer eligible';
                        END IF;
                    END IF;
                END LOOP;
            END;
        END IF;
    """
