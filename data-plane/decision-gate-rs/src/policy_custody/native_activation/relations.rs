//! Closed native consume relation contract. No packet supplies a table, key
//! recipe, mutation template or authorization class to this verifier.
use super::*;
pub(super) const AUTHORIZATION:&[&str]=&["policy_authority_trusted_keys","policy_candidate_artifacts","rbac_role_bindings",
    "webauthn_trust_publication_high_water","webauthn_trust_publications"];
const RELATIONS:&[(&str,&[&str])]=&[
    ("control_plane_approvals",&["id"]),("metadata_audit_outbox",&["id"]),
    ("policy_activation_approval_consumptions",&["approval_id"]),("policy_activation_attempts",&["activation_attempt_id"]),
    ("policy_activation_finalizations",&["preparation_digest"]),("policy_activation_heads",&["activation_attempt_id"]),
    ("policy_activation_preparations",&["preparation_digest"]),("policy_activation_prepared_transitions",&["preparation_digest","transition_ordinal"]),
    ("policy_activation_publication_receipts",&["publication_receipt_envelope_digest"]),("policy_activation_rollback_authority_revocations",&["revocation_envelope_digest"]),
    ("policy_authority_audit_inclusion_receipts",&["inclusion_receipt_envelope_digest"]),
    ("policy_authority_bounded_aggregate_states",&["aggregate_id"]),("policy_authority_evidence_verifications",&["verification_receipt_digest"]),
    ("policy_authority_genesis_finalizations",&["genesis_preparation_digest"]),("policy_authority_genesis_preparations",&["genesis_preparation_digest"]),
    ("policy_authority_trusted_key_heads",&["evidence_kind"]),("policy_authority_trusted_key_revocations",&["evidence_kind","signing_key_id"]),
    ("policy_authority_trusted_keys",&["evidence_kind","key_revision"]),("policy_canaries",&["canary_id"]),
    ("policy_canary_active_decisions",&["active_decision_envelope_digest"]),("policy_canary_assignment_members",&["assignment_envelope_digest","member_ordinal"]),
    ("policy_canary_assignments",&["assignment_envelope_digest"]),("policy_canary_checkpoint_aggregates",&["canary_id","instance_id","boot_id","checkpoint_sequence"]),
    ("policy_canary_checkpoint_heads",&["canary_id","instance_id","boot_id"]),("policy_canary_checkpoints",&["canary_id","instance_id","boot_id","checkpoint_sequence"]),
    ("policy_canary_custody_evidence",&["custody_evidence_envelope_digest"]),
    ("policy_canary_custody_heads",&["assignment_envelope_digest","member_ordinal","canary_id","instance_id","boot_id","generation_id_digest"]),
    ("policy_canary_delivery_heads",&["id"]),("policy_canary_delivery_slots",&["id"]),("policy_canary_heads",&["canary_id"]),
    ("policy_canary_ingress_observations",&["ingress_envelope_digest"]),("policy_canary_instance_heads",&["canary_id","instance_id","boot_id"]),
    ("policy_canary_instance_revisions",&["canary_id","instance_id","boot_id","revision"]),("policy_canary_instances",&["canary_id","instance_id","boot_id"]),
    ("policy_canary_intake_batches",&["request_id"]),("policy_canary_load_receipts",&["load_receipt_envelope_digest"]),
    ("policy_canary_readiness",&["readiness_envelope_digest"]),("policy_canary_revisions",&["canary_id","revision"]),
    ("policy_canary_shadow_observations",&["shadow_observation_envelope_digest"]),("policy_candidate_artifacts",&["artifact_envelope_digest"]),
    ("policy_compiler_authority_analyses",&["analysis_envelope_digest"]),("policy_high_water",&["scope"]),
    ("policy_native_activation_finalizations",&["canary_id"]),("policy_native_activation_holds",&["scope"]),
    ("policy_native_activation_preparations",&["canary_id"]),("policy_native_canary_heads",&["canary_id"]),("policy_native_canary_ready",&["canary_id"]),
    ("policy_publications",&["policy_hash"]),("policy_runtime_attestations",&["attestation_receipt_envelope_digest"]),
    ("policy_runtime_evidence_verifications",&["verification_receipt_digest"]),("policy_runtime_role_key_revocations",&["revocation_envelope_digest"]),
    ("policy_runtime_role_keys",&["assignment_envelope_digest","member_ordinal","role","public_key_digest"]),
    ("policy_shadow_generation_publications",&["generation_publication_envelope_digest"]),("policy_shadow_runtime_attestation_handoffs",&["runtime_attestation_handoff_digest"]),
    ("rbac_role_bindings",&["subject_id"]),("webauthn_challenges",&["id"]),("webauthn_credentials",&["id"]),
    ("webauthn_trust_publication_high_water",&["authority_scope"]),("webauthn_trust_publications",&["id"]),
];
pub(super) fn tables()->Vec<&'static str>{let mut names=RELATIONS.iter().map(|r|r.0).collect::<Vec<_>>();names.sort();names}
pub(in crate::policy_shadow::native_activation) fn population_tables()->Vec<&'static str>{tables().into_iter().filter(|t|!matches!(*t,
    "control_plane_approvals"|"metadata_audit_outbox"|"policy_authority_bounded_aggregate_states"|"rbac_role_bindings"|
    "webauthn_challenges"|"webauthn_credentials"|"webauthn_trust_publication_high_water"|"webauthn_trust_publications")).collect()}
pub(super) fn key_columns(table:&str)->Result<&'static [&'static str],ShadowError>{
    RELATIONS.iter().find(|r|r.0==table).map(|r|r.1).ok_or(ShadowError::BindingDrift)
}
pub(super) fn writable(table:&str)->bool{["control_plane_approvals","metadata_audit_outbox","policy_authority_bounded_aggregate_states",
    "policy_canary_heads","policy_high_water","policy_native_activation_finalizations","policy_native_activation_holds",
    "policy_native_activation_preparations","policy_native_canary_heads","policy_native_canary_ready","policy_publications","webauthn_challenges","webauthn_credentials"].contains(&table)}
pub(super) fn kinds(table:&str)->&'static [&'static str]{match table{
    "policy_authority_bounded_aggregate_states"|"policy_canary_heads"|"policy_high_water"=>&["UPDATE"],
    "policy_native_canary_ready"|"policy_native_activation_finalizations"|"policy_publications"=>&["INSERT"],
    _ if writable(table)=>&["INSERT","UPDATE"],_=>&[],
}}
pub(super) fn tree(domain:&str,frames:&[&[u8]])->Sha256Digest{
    let mut h=Sha256::new();h.update((domain.len() as u64).to_be_bytes());h.update(domain.as_bytes());
    for frame in frames{h.update((frame.len() as u64).to_be_bytes());h.update(frame);}
    Sha256Digest(format!("sha256:{}",hex::encode(h.finalize())))
}
pub(super) fn template(table:&str,kind:&str)->Result<Value,ShadowError>{
    require(kinds(table).contains(&kind))?;
    let mut v=json!({"schema":"serverware.policyAuthorityMutationTemplate/v1","operation":OPERATION,"table":table,"mutation":kind,
        "before":if kind=="INSERT"{"absent"}else{"present"},"after":"present","predicate":"exact-primary-key-and-full-row-cas-v1","cardinality":1});
    v["templateId"]=serde_json::to_value(tree("serverware.policyAuthorityMutationTemplate/v1",&[&canonical_json_bytes(&v)?])).map_err(fail)?;Ok(v)
}
pub(in crate::policy_shadow::native_activation) fn guard_commitment()->Result<Sha256Digest,ShadowError>{Ok(Sha256Digest::compute(&canonical_json_bytes(&json!({
    "apiVersion":"serverware.nativePolicyActivationEffectGuard/v1","scope":"native-policy-publication",
    "authority":"all-source-admitted-controlled-business-and-authorization-mutations",
    "serialization":"exclusive-held-table-lock-before-any-business-mutation",
    "exemptTables":["metadata_audit_outbox","policy_authority_bounded_aggregate_states","policy_authority_transition_audits"],
    "ownerOperations":["native-policy-activation.record-inclusion","native-policy-activation.finalize"],
    "expiryUnlockAllowed":false,"unknownEffectUnlockAllowed":false}))?))}
pub(in crate::policy_shadow::native_activation) fn handler_commitment(source:&str)->Result<Sha256Digest,ShadowError>{
    let tables=tables();let writes=tables.iter().copied().filter(|t|writable(t)).collect::<Vec<_>>();
    let reads=tables.iter().copied().filter(|t|!writable(t)&&!AUTHORIZATION.contains(t)).collect::<Vec<_>>();
    let pre=["policy_authority_authorization_dependency_manifests","policy_authority_fence_heads","policy_authority_query_dependency_manifests"];
    let fw=["policy_authority_authenticated_leaves","policy_authority_authenticated_root_revisions","policy_authority_authenticated_table_roots",
        "policy_authority_authenticated_tree_nodes","policy_authority_authorization_projections","policy_authority_consumed_envelopes",
        "policy_authority_execution_envelopes","policy_authority_planner_transactions","policy_authority_webauthn_assertion_evidence",
        "policy_authority_writer_capabilities","policy_authority_writer_receipts"];
    let rbw=["policy_authority_authorization_projections","policy_authority_execution_envelopes","policy_authority_planner_transactions",
        "policy_authority_webauthn_assertion_evidence","policy_authority_writer_capabilities"];
    let mut all_reads=tables.clone();all_reads.extend(pre);all_reads.extend(fw);all_reads.sort();all_reads.dedup();
    let mut all_writes=writes.clone();all_writes.extend(fw);all_writes.sort();all_writes.dedup();
    let mut templates=Vec::new();for table in &writes{for kind in kinds(table){templates.push(template(table,kind)?);}}
    let transition=tree("serverware.policyAuthorityTransitionProgram/v1",&[&canonical_json_bytes(&json!({"operation":OPERATION,"handler":HANDLER}))?]);
    let stem=OPERATION.replace(['.','-'],"_");let suffix=hex::encode(Sha256::digest(OPERATION.as_bytes()));
    let prefix="serverware_policy_authority_execute_";let tail=format!("_{}_v9",&suffix[..12]);
    let executor=format!("{prefix}{}{tail}",&stem[..stem.len().min(63-prefix.len()-tail.len())]);
    Ok(tree("serverware.policyAuthorityHandlerContract/v1",&[&canonical_json_bytes(&json!({
        "sourceRevision":source,"operation":OPERATION,"handler":HANDLER,
        "transitionProgramId":format!("serverware.policyAuthorityTransition/{}/{}/v1",OPERATION,&transition.as_str()[7..23]),
        "planningMode":"typed-pure-transition","businessReads":reads,"businessWrites":writes,"businessReadBeforeWrite":writes,
        "authorizationReads":AUTHORIZATION,"frameworkPreconditions":pre,"frameworkWrites":fw,"frameworkReadBeforeWrite":rbw,
        "mutationTemplates":templates,"executorFunction":executor,"executorIdentityArguments":["text","text","text","text","text"],
        "reads":all_reads,"writes":all_writes,"selectors":{},"webauthn":"bound-verified-assertion-receipt","assertionRequired":true,"approverPolicyRequired":false,
        "proofPrimitives":["primary-key-row","bounded-limit-plus-one","aggregate-high-water","capacity-reservation"],"completeIndexQueryRoles":[],
        "globalAuditCapacity":true,"auditCapacityCounterSlotsReplaced":0,"auditCapacityAddsAggregateRoot":false,
        "maximumBusinessQueryRows":256,"maximumBusinessMutations":16,"maximumBusinessWorkUnits":8192,
        "maximumQueryRows":257,"maximumMutations":17,"maximumWorkUnits":8194,"externalEvidenceTypes":[],"opaqueValueKinds":[]}))?]))
}
