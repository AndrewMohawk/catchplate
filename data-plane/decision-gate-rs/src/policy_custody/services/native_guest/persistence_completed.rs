//! Read-only completion export under independently selected v2/v3 grants.
//! Completion records an exact protocol result, not business success, process
//! death, timeout-cleanup authority, or closure of other service journals.
use super::*;
use crate::policy_shadow::policy_custody::native_terminal::{Query,Proof};

impl Service {
    pub(super) fn completed_invocation(&self,request:&Request,query:&Query,keys:&AdmittedKeys,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Proof,ShadowError>{
        require(matches!(self.configuration.payload.api_version.as_str(),
            "catchplate.nativeShadowPersistenceServiceAssignment/v2"|"catchplate.nativeShadowPersistenceServiceAssignment/v3"|"catchplate.nativeShadowPersistenceServiceAssignment/v4")
            && self.configuration.payload.permissions.contains(&Permission::VerifyCompletedInvocation))?;
        if query.publication_selected() {
            require(matches!(self.configuration.payload.api_version.as_str(),"catchplate.nativeShadowPersistenceServiceAssignment/v3"|"catchplate.nativeShadowPersistenceServiceAssignment/v4")
                && self.configuration.payload.permissions.contains(&Permission::VerifyPublicationInvocation))?;
        }
        query.validate().map_err(fail)?;let binding=query.dispatch.binding();let now=guest::now()?;
        require(request.replay_id_sha256==binding.replay_id_sha256
            && request.deadline_boottime_nanos==binding.cleanup_deadline_boottime_nanos
            && binding.opened_at_boottime_nanos<=now && now<binding.cleanup_deadline_boottime_nanos)?;
        self.check(keys,trust,time)?;
        let mut selected=None;
        for commit in self.store.originals() {
            let (prior,_):(Request,_)=original(&commit.payload.request_original_base64url)?;
            if final_dispatch(&prior)?.binding().operation_id_sha256==binding.operation_id_sha256 {
                require(selected.is_none())?;selected=Some(commit);
            }
        }
        let commit=selected.ok_or(ShadowError::CustodyUnavailable)?;let payload=&commit.payload;
        let (prior,_,_)=dispatch_original(&payload.request_original_base64url,&payload.reply_original_base64url,
            &self.scope,self.configuration.payload.adoption.as_deref(),keys,trust,time)?;
        self.require_selected_final(&prior)?;
        if services::publication_client::selected(&query.dispatch) {
            require(query.publication_selected() && matches!(prior.request,Body::FinishNativePublication{..}))?;
        }
        let (reply,_):(Reply,_)=original(&payload.reply_original_base64url)?;
        let ResultBody::Dispatch(response)=&reply.result else{return Err(ShadowError::BindingDrift);};
        require(final_dispatch(&prior)?==&query.dispatch
            && Sha256Digest::compute(&canonical_json_bytes(response)?)==query.dispatch_response_sha256
            && payload.original_deadline_boottime_nanos==binding.operation_deadline_boottime_nanos
            && payload.stored_at_boottime_nanos>=reply.completed_at_boottime_nanos
            && payload.stored_at_boottime_nanos<=guest::now()?)?;
        let (commit_raw,head_raw,current_head_sequence,current_head_sha256)=self.store.completed_originals(payload.sequence)?;
        // ASCII JSON originals escape at most twice when nested as strings.
        // Reserve fixed envelope/signature overhead before encoding anything;
        // the normal endpoint encoder still enforces its unchanged hard cap.
        require(commit_raw.is_ascii() && head_raw.is_ascii()
            && commit_raw.len().checked_add(head_raw.len()).and_then(|n|n.checked_mul(2))
                .and_then(|n|n.checked_add(4096)).is_some_and(|n|n<=services::common::MAX_SERVICE_FRAME_BYTES))?;
        let proof=Proof{api_version:query.proof_api().into(),commit_original:String::from_utf8(commit_raw).map_err(fail)?,
            head_original:String::from_utf8(head_raw).map_err(fail)?,current_head_sequence,current_head_sha256};
        self.check(keys,trust,time)?;require(guest::now()?<binding.cleanup_deadline_boottime_nanos)?;Ok(proof)
    }
}
