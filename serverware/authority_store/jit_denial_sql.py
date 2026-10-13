"""Independent writer veto for the exact one-actor JIT denial transition.

Uses only admitted capability/planner rows inside the existing SERIALIZABLE
executor, after its current assertion/challenge/counter guards. No standalone
authority, commit, vote discovery, grant creation or legacy evidence adapter.
"""
from __future__ import annotations

from serverware.authority_store.mutation_sql import _schema_name


def assert_jit_denial_sql(namespace: str) -> str:
    """Require the exact selected originals and capability-bound denial plan."""
    _schema_name(namespace)
    selections = (("deny_approval", "approval_requests"),
        ("deny_review", "approval_review_receipts"),
        ("deny_credential", "webauthn_credentials"),
        ("deny_challenge", "webauthn_challenges"))
    selected_sql = "\n".join(f"""
                SELECT pg_catalog.count(*) INTO deny_count
                FROM pg_catalog.jsonb_array_elements(planner.selected_business_rows_json::pg_catalog.jsonb) AS item(value)
                WHERE item.value->>'table' = '{table}';
                IF deny_count <> 1 THEN
                    RAISE EXCEPTION 'authority JIT denial original selection is not exact';
                END IF;
                SELECT item.value->'row' INTO STRICT {variable}
                FROM pg_catalog.jsonb_array_elements(planner.selected_business_rows_json::pg_catalog.jsonb) AS item(value)
                WHERE item.value->>'table' = '{table}' AND item.value->'present' = 'true'::pg_catalog.jsonb;
                SELECT pg_catalog.count(*) INTO deny_count
                FROM pg_catalog.jsonb_array_elements(planner.mutation_plan_json::pg_catalog.jsonb) AS item(value)
                WHERE item.value->>'table' = '{table}';
                IF deny_count <> 1 THEN
                    RAISE EXCEPTION 'authority JIT denial mutation roster is not exact';
                END IF;
                SELECT item.value INTO STRICT {variable}_mutation
                FROM pg_catalog.jsonb_array_elements(planner.mutation_plan_json::pg_catalog.jsonb) AS item(value)
                WHERE item.value->>'table' = '{table}' AND item.value->>'operation' = 'UPDATE';
                IF ({variable}_mutation->'expectedRow' = {variable}
                    AND {variable}_mutation->'key' = pg_catalog.jsonb_build_object('id', {variable}->'id')
                ) IS NOT TRUE THEN
                    RAISE EXCEPTION 'authority JIT denial original mutation binding changed';
                END IF;
        """ for variable, table in selections)
    return f"""
        IF capability.operation = 'jit.deny' THEN
            DECLARE
                deny_approval pg_catalog.jsonb;
                deny_review pg_catalog.jsonb;
                deny_credential pg_catalog.jsonb;
                deny_challenge pg_catalog.jsonb;
                deny_approval_mutation pg_catalog.jsonb;
                deny_review_mutation pg_catalog.jsonb;
                deny_credential_mutation pg_catalog.jsonb;
                deny_challenge_mutation pg_catalog.jsonb;
                deny_result pg_catalog.jsonb;
                deny_policy pg_catalog.jsonb;
                deny_authn pg_catalog.jsonb;
                deny_actor text;
                deny_used text;
                deny_count bigint;
                deny_now numeric;
                deny_policy_digest text;
            BEGIN
                {selected_sql}
                deny_result := deny_approval_mutation->'row';
                deny_actor := deny_result->>'approved_by';
                deny_used := deny_review_mutation->'row'->>'used_at';
                deny_now := pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000000);
                IF deny_now < now_epoch_ns OR deny_now >= capability.deadline_epoch_ns THEN
                    RAISE EXCEPTION 'authority JIT denial original deadline expired';
                END IF;
                deny_policy := (deny_approval->>'approver_policy_json')::pg_catalog.jsonb;
                deny_policy_digest := {namespace}.serverware_policy_authority_domain_digest(
                    'serverware.authorityApproverPolicyBinding/v1',
                    {namespace}.serverware_policy_authority_wire_json(pg_catalog.jsonb_build_object(
                        'schema', 'serverware.authorityApproverPolicyBinding/v1',
                        'requiredApproverRoles', deny_policy->'requiredRoles',
                        'allowedApproverIds', deny_policy->'allowedApproverIds',
                        'allowAnyApproverId', deny_policy->'allowAnyApproverId',
                        'requireWebAuthn', deny_policy->'requireWebAuthn',
                        'threshold', deny_policy->'threshold',
                        'credentialPolicy', deny_policy->'credentialPolicy')));
                deny_authn := pg_catalog.jsonb_build_object(
                    'schema', 'serverware.jitDenialAuthnReceipt/v3',
                    'approverPolicyDigest', deny_approval->>'approver_policy_digest',
                    'verifiedAssertionReceiptDigest', capability.webauthn_receipt_digest,
                    'authorityCapabilityId', capability.capability_id,
                    'authorityRequestDigest', capability.request_digest,
                    'reviewReceiptId', deny_review->>'id',
                    'reviewDigest', deny_review->>'review_digest');
                IF (deny_approval->>'status' = 'pending'
                    AND deny_approval->'approved_until' = 'null'::pg_catalog.jsonb
                    AND EXTRACT(EPOCH FROM (deny_approval->>'expires_at')::timestamptz) * 1000000000 > deny_now
                    AND deny_policy->>'schema' = 'serverware.jitApproverPolicy/v1'
                    AND deny_policy->'requireWebAuthn' = 'true'::pg_catalog.jsonb
                    AND deny_approval->>'approver_policy_json' =
                        {namespace}.serverware_policy_authority_wire_json(deny_policy)
                    AND deny_approval->>'approver_policy_digest' =
                        {namespace}.serverware_policy_authority_domain_digest(
                            'serverware.jitApproverPolicy/v1', deny_approval->>'approver_policy_json')
                    AND capability.approver_policy_digest = deny_policy_digest
                    AND (deny_policy->'allowAnyApproverId' = 'true'::pg_catalog.jsonb
                        OR deny_policy->'allowedApproverIds' ? deny_actor)
                    AND (deny_policy->'requiredRoles' = '[]'::pg_catalog.jsonb OR (
                        deny_actor LIKE 'oidc:%' AND EXISTS (
                            SELECT 1 FROM pg_catalog.jsonb_array_elements(
                                planner.selected_business_rows_json::pg_catalog.jsonb) AS binding(value)
                            WHERE binding.value->>'table' = 'rbac_role_bindings'
                              AND binding.value->'row'->>'subject_id' = deny_actor
                              AND binding.value->'row'->>'status' = 'active'
                              AND EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements_text(
                                  (binding.value->'row'->>'roles_json')::pg_catalog.jsonb) AS role(value)
                                  WHERE deny_policy->'requiredRoles' ? role.value))))
                    AND EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(
                        planner.selected_business_rows_json::pg_catalog.jsonb) AS policy(value)
                        WHERE policy.value->>'table' = 'policy_high_water'
                          AND policy.value->'row'->>'scope' = 'global'
                          AND policy.value->'row'->'policy_hash' = deny_approval->'policy_hash')
                    AND deny_review->'approval_request_id' = deny_approval->'id'
                    AND deny_review->>'reviewer_id' = deny_actor
                    AND deny_review->'used_at' = 'null'::pg_catalog.jsonb
                    AND EXTRACT(EPOCH FROM (deny_review->>'expires_at')::timestamptz) * 1000000000 > deny_now
                    AND deny_used IS NOT NULL
                    AND EXTRACT(EPOCH FROM deny_used::timestamptz) * 1000000000 <= deny_now
                    AND deny_review_mutation->'row' = deny_review || pg_catalog.jsonb_build_object('used_at', deny_used)
                    AND deny_credential->>'id' = capability.webauthn_receipt_json::pg_catalog.jsonb->>'credentialRecordId'
                    AND deny_challenge->>'id' = capability.webauthn_receipt_json::pg_catalog.jsonb->>'challengeId'
                    AND deny_credential->>'user_id' = deny_actor
                    AND deny_challenge->>'user_id' = deny_actor
                    AND deny_challenge_mutation->'row'->>'used_at' = deny_used
                    AND deny_credential_mutation->'row'->>'last_used_at' = deny_used
                    AND deny_challenge_mutation->'row' =
                        deny_challenge || pg_catalog.jsonb_build_object('used_at', deny_used)
                    AND deny_credential_mutation->'row' = deny_credential || pg_catalog.jsonb_build_object(
                        'sign_count', capability.webauthn_receipt_json::pg_catalog.jsonb->'counter',
                        'last_used_at', deny_used, 'updated_at', deny_used)
                    AND deny_result = deny_approval || pg_catalog.jsonb_build_object(
                        'status', 'denied', 'decision_note', deny_result->'decision_note', 'approved_by', deny_actor,
                        'approval_authn', {namespace}.serverware_policy_authority_wire_json(deny_authn),
                        'approver_webauthn_credential_id', deny_credential->>'id',
                        'verified_assertion_receipt_digest', capability.webauthn_receipt_digest,
                        'approval_challenge_id', deny_challenge->>'id')
                ) IS NOT TRUE THEN
                    RAISE EXCEPTION 'authority JIT denial capability or original review binding changed';
                END IF;
                SELECT pg_catalog.count(*) INTO deny_count
                FROM pg_catalog.jsonb_array_elements(planner.selected_business_rows_json::pg_catalog.jsonb) AS item(value)
                WHERE item.value->>'table' = 'approval_grants';
                IF deny_count <> 1 OR NOT EXISTS (
                    SELECT 1 FROM pg_catalog.jsonb_array_elements(planner.selected_business_rows_json::pg_catalog.jsonb) AS item(value)
                    WHERE item.value->>'table' = 'approval_grants'
                      AND item.value->'key' = pg_catalog.jsonb_build_object('id', 'approval:' || (deny_approval->>'id'))
                      AND item.value->'present' = 'false'::pg_catalog.jsonb AND item.value->'row' = 'null'::pg_catalog.jsonb
                ) OR EXISTS (
                    SELECT 1 FROM pg_catalog.jsonb_array_elements(planner.mutation_plan_json::pg_catalog.jsonb) AS item(value)
                    WHERE item.value->>'table' IN ('approval_grants', 'approval_grant_consumptions', 'approval_request_decisions')
                ) THEN
                    RAISE EXCEPTION 'authority JIT denial cannot create a grant or vote';
                END IF;
            END;
        END IF;
    """
