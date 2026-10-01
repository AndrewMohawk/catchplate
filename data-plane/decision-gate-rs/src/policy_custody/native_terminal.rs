//! Explicit successful-invocation successor. These are data-only wire values;
//! authenticity and completion come from retained owners and the verifier.
use super::production_dispatch::ClosedProductionDispatchRequestV4;
use super::super::Sha256Digest;
use super::protocol::PolicyCustodyOperation;
use serde::{Deserialize,Serialize};

pub(in crate::policy_shadow) const RUNTIME:&str="serverware.policyCustodyProductionRpcRuntime/v12";
pub(in crate::policy_shadow) const QUERY_API:&str="serverware.nativeCompletedInvocationQuery/v1";
pub(in crate::policy_shadow) const PROOF_API:&str="serverware.nativeCompletedInvocationProof/v1";
pub(in crate::policy_shadow) const WIRE_API:&str="serverware.nativeInvocationSettlement/v1";

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow) struct Query {
    pub(in crate::policy_shadow) api_version:String,
    pub(in crate::policy_shadow) dispatch:ClosedProductionDispatchRequestV4,
    pub(in crate::policy_shadow) dispatch_response_sha256:Sha256Digest,
    pub(in crate::policy_shadow) cleanup_not_before_boottime_nanos:u64,
}
impl Query {
    pub(in crate::policy_shadow) fn validate(&self)->Result<(),&'static str>{
        self.dispatch.validate()?;
        if self.api_version!=QUERY_API
            || self.cleanup_not_before_boottime_nanos!=self.dispatch.binding().operation_deadline_boottime_nanos
            || !matches!(self.dispatch.operation(),PolicyCustodyOperation::BeginIngress
                |PolicyCustodyOperation::CommitRequest|PolicyCustodyOperation::ReserveSpoolAppend
                |PolicyCustodyOperation::AppendSpoolEvent|PolicyCustodyOperation::AppendTerminal
                |PolicyCustodyOperation::AppendActiveEffectBarrier|PolicyCustodyOperation::CommitActiveEffect
                |PolicyCustodyOperation::ReconcileActiveEffect) {
            return Err("native completed invocation query is outside the selected final protocol");
        }
        Ok(())
    }
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow) struct Proof {
    pub(in crate::policy_shadow) api_version:String,
    pub(in crate::policy_shadow) commit_original:String,
    pub(in crate::policy_shadow) head_original:String,
    pub(in crate::policy_shadow) current_head_sequence:u64,
    pub(in crate::policy_shadow) current_head_sha256:Sha256Digest,
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow) struct Wire {
    pub(in crate::policy_shadow) api_version:String,
    pub(in crate::policy_shadow) persistence_request_original:String,
    pub(in crate::policy_shadow) persistence_reply_original:String,
    pub(in crate::policy_shadow) dispatch_request_original_sha256:Sha256Digest,
    pub(in crate::policy_shadow) dispatch_response_original_sha256:Sha256Digest,
}

#[cfg(test)]
#[path="native_terminal_tests.rs"]
mod tests;
