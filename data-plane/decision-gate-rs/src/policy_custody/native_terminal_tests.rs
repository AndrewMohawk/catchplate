//! Pure wire controls, not a live permit, factory, signer, journal or success
//! fixture. Synthetic identities use the real closed-binding hash constructor.
use super::*;
use super::super::production_dispatch::{ClosedProductionDispatchRequestV4 as Dispatch,
    ProductionDispatchBindingV4 as Binding};

fn binding(operation:PolicyCustodyOperation,opened:u64,operation_deadline:u64,cleanup_deadline:u64)->Binding {
    Binding::from_verified_parent_permit(operation,Sha256Digest::compute(b"synthetic-operation"),
        Sha256Digest::compute(b"synthetic-request"),Sha256Digest::compute(b"synthetic-durable-request"),
        Sha256Digest::compute(b"synthetic-fence"),Sha256Digest::compute(b"synthetic-configuration"),
        Sha256Digest::compute(b"synthetic-driver"),Sha256Digest::compute(b"synthetic-descriptors"),
        Sha256Digest::compute(b"synthetic-generation"),opened,operation_deadline,cleanup_deadline).unwrap()
}
fn begin(opened:u64,operation_deadline:u64,cleanup_deadline:u64)->Dispatch {
    Dispatch::BeginIngress{binding:binding(PolicyCustodyOperation::BeginIngress,opened,operation_deadline,cleanup_deadline),
        request_binding_sha256:Sha256Digest::compute(b"synthetic-request-binding")}
}
fn query(dispatch:Dispatch)->Query {
    Query{api_version:QUERY_API.into(),cleanup_not_before_boottime_nanos:dispatch.binding().operation_deadline_boottime_nanos,
        dispatch,dispatch_response_sha256:Sha256Digest::compute(b"synthetic-response-not-evidence")}
}

#[test]
fn accepts_closed_ingress_and_reconcile_operations_without_claiming_completion() {
    assert!(query(begin(10,20,30)).validate().is_ok());
    let dispatch=Dispatch::ReconcileActiveEffect{
        binding:binding(PolicyCustodyOperation::ReconcileActiveEffect,10,20,30),
        generation_id:Sha256Digest::compute(b"synthetic-generation"),ingress_sequence:1,
        effect_id_sha256:Sha256Digest::compute(b"synthetic-effect")};
    assert!(query(dispatch).validate().is_ok());
}

#[test]
fn valid_legacy_recovery_is_not_a_completed_invocation_query() {
    let dispatch=Dispatch::RecoverCurrentState{
        binding:binding(PolicyCustodyOperation::RecoverCurrentState,10,20,30)};
    assert!(dispatch.validate().is_ok());
    assert!(query(dispatch).validate().is_err());
}

#[test]
fn cleanup_marker_is_the_original_operation_deadline_not_a_new_issue_time() {
    let original=query(begin(10,20,30));
    assert!(original.validate().is_ok());
    for marker in [0,10,19,21,30] {
        let mut changed=original.clone();changed.cleanup_not_before_boottime_nanos=marker;
        assert!(changed.validate().is_err());
    }
    // There is deliberately no current-time argument or waiting decision in
    // this data-only query; actual owner/receiver checks bracket proof use.
}

#[test]
fn modified_original_binding_is_not_repaired_by_the_query() {
    let mut changed=query(begin(10,20,30));
    let Dispatch::BeginIngress{binding,..}=&mut changed.dispatch else{unreachable!()};
    binding.termination_fence_sha256=Sha256Digest::compute(b"different-fence");
    assert!(changed.validate().is_err());
    let mut changed=query(begin(10,20,30));
    let Dispatch::BeginIngress{binding,..}=&mut changed.dispatch else{unreachable!()};
    binding.operation=PolicyCustodyOperation::RecoverCurrentState;
    assert!(changed.validate().is_err());
}

#[test]
fn query_version_and_closed_camel_case_fields_are_exact() {
    let original=query(begin(10,20,30));
    let mut wrong=original.clone();wrong.api_version="serverware.nativeCompletedInvocationQuery/v2".into();
    assert!(wrong.validate().is_err());
    let mut value=serde_json::to_value(&original).unwrap();
    assert!(value.get("cleanupNotBeforeBoottimeNanos").is_some());
    value.as_object_mut().unwrap().insert("success".into(),serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<Query>(value).is_err());
    let mut value=serde_json::to_value(&original).unwrap();
    value.as_object_mut().unwrap().remove("dispatchResponseSha256");
    assert!(serde_json::from_value::<Query>(value).is_err());
}

#[test]
fn original_boottime_fields_preserve_native_u64_limits() {
    let original=query(begin(u64::MAX-2,u64::MAX-1,u64::MAX));
    assert!(original.validate().is_ok());
    let decoded:Query=serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
    assert_eq!(decoded,original);
    assert!(Binding::from_verified_parent_permit(PolicyCustodyOperation::BeginIngress,
        Sha256Digest::compute(b"o"),Sha256Digest::compute(b"r"),Sha256Digest::compute(b"d"),
        Sha256Digest::compute(b"f"),Sha256Digest::compute(b"c"),Sha256Digest::compute(b"k"),
        Sha256Digest::compute(b"s"),Sha256Digest::compute(b"g"),10,20,20).is_err());
}

#[test]
fn explicit_publication_query_is_required_for_recovery() {
    let mut value=query(Dispatch::RecoverCurrentState{
        binding:binding(PolicyCustodyOperation::RecoverCurrentState,10,20,30)});
    assert!(value.validate().is_err());
    value.api_version=Query::api_for_publication(true).into();
    assert!(value.publication_selected());
    assert_eq!(value.proof_api(),PUBLICATION_PROOF_API);
    assert!(value.validate().is_ok());
    value.api_version="serverware.nativeCompletedInvocationQuery/v3".into();
    assert!(value.validate().is_err());
}

#[test]
fn publication_query_keeps_old_operations_and_original_cleanup_marker() {
    let mut value=query(begin(10,20,30));
    value.api_version=PUBLICATION_QUERY_API.into();
    assert!(value.validate().is_ok());
    // Early successful final completion may be exported before the operation
    // deadline; this immutable marker is not a destructive cleanup timer.
    for changed in [10,19,21,30] {
        let mut altered=value.clone();altered.cleanup_not_before_boottime_nanos=changed;
        assert!(altered.validate().is_err());
    }
    value.api_version=Query::api_for_publication(false).into();
    assert_eq!(value.proof_api(),PROOF_API);
    assert!(value.validate().is_ok());
}

#[test]
fn publication_commit_and_abort_shapes_do_not_expand_legacy_query() {
    use super::super::production_dispatch::{CanonicalProductionArtifactV4 as Artifact,ProductionArtifactKindV4 as Kind};
    // Deliberately data-only artifact: Query checks closed routing/binding,
    // while the real producer/receiver must authenticate the complete type.
    let prepared=Artifact::from_serializable(Kind::PreparedGenerationPublication,&serde_json::json!({"synthetic":"shape-only"})).unwrap();
    for dispatch in [
        Dispatch::CommitGenerationPublication{binding:binding(PolicyCustodyOperation::CommitGenerationPublication,10,20,30),prepared:prepared.clone()},
        Dispatch::AbortGenerationPublication{binding:binding(PolicyCustodyOperation::AbortGenerationPublication,10,20,30),prepared},
    ] {
        let mut value=query(dispatch);
        assert!(value.validate().is_err());
        value.api_version=PUBLICATION_QUERY_API.into();
        assert!(value.validate().is_ok());
        assert_eq!(value.proof_api(),PUBLICATION_PROOF_API);
    }
}
