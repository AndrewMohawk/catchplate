//! Actual same-process activated configuration guard. This does not serialize
//! the native closure owner or manufacture the external gate's RPC facade.
use super::*;
use crate::policy_shadow::policy_custody::production_dispatch::ClosedProductionGenerationRequestV4 as Request;

impl AdmittedGuest {
    pub(in crate::policy_shadow::policy_custody::services) fn require_native_generation(&self,request:&Request)->Result<(),ShadowError>{
        let Some(configuration)=self.active_native_configuration()? else{return Ok(());};
        require(request.deadline_boottime_nanos()<=self.delivery().lifetime)?;
        let (binding,driver,descriptors,context)=match request {
            Request::Recover{successor_configuration_binding_sha256,kernel_driver_identity_sha256,retained_descriptor_set_sha256,install_context,..}
            |Request::Prepare{successor_configuration_binding_sha256,kernel_driver_identity_sha256,retained_descriptor_set_sha256,install_context,..}
                =>(successor_configuration_binding_sha256,kernel_driver_identity_sha256,retained_descriptor_set_sha256,install_context),
            // Commit/abort retain the existing exact preparation/journal
            // checks; they cannot introduce a different generation scope.
            Request::Commit{..}|Request::Abort{..}=>return Ok(()),
        };
        let retained=self.delivery().native_continuation.as_ref().ok_or(ShadowError::BindingDrift)?;
        let actual=retained.driver_identity()?;
        let assignment=configuration.retained_verified_assignment.payload();
        let checkpoint=self.trust.current_checkpoint()?;
        let key=assignment.authority_key_independence.binding(AuthorityRole::CustodyResultEnvelope,&assignment.assignment_id)?;
        require(binding==configuration.production_configuration_binding_sha256()
            && driver==actual.identity_sha256() && descriptors==&actual.retained_descriptor_manifest_sha256
            && context.assignment_id==assignment.assignment_id
            && context.assignment_payload_sha256==*configuration.assignment_payload_sha256()
            && context.assignment_revision==configuration.assignment_revision()
            && context.operation_coverage_root_sha256==*configuration.operation_coverage_root_sha256()
            && context.five_service_protocol_set_sha256==*configuration.dispatcher_protocol_set_sha256()
            && context.envelope_authority_key_id==key.key_id && context.envelope_authority_key_spki_sha256==key.key_spki_sha256
            && context.trusted_time_checkpoint_sha256==checkpoint.checkpoint_id
            && context.trusted_time_revocation_generation==checkpoint.revocation_generation
            && context.trusted_time_revocation_root_sha256==checkpoint.revocation_root_sha256
            && context.expires_at_unix_nanos<=assignment.expires_at_unix_nanos)?;
        validate_trusted_freshness(context.issued_at_unix_nanos,context.expires_at_unix_nanos,self.time.as_ref(),MAX_ENVELOPE_AGE_NANOS)?;
        self.check()
    }
}
