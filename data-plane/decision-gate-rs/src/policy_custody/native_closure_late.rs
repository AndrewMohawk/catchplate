//! Acyclic closure successor. The immutable image contains only bootstrap
//! runtime. Full operational C9/runtime remains covered by the independent
//! phase-two and closure signatures; no field is excluded from either signature.
use super::*;
use policy_custody::services::guest::native_guest::driver_continuation::Retained;

impl Configuration {
    pub(in crate::policy_shadow) fn require_late_image(&self,owner:&Retained)->Result<(),ShadowError>{
        owner.check_startup()?;require(self.api_version=="serverware.nativeCustodyClosure/v2")?;
        self.manifest.validate()?;let m=&self.manifest;
        require(m.profile==BOOTSTRAP_PROFILE && m.image_sha256==*owner.image_sha256()
            && m.worker_executable_sha256==*owner.executable_sha256()
            && m.runtime_configuration_sha256==*owner.bootstrap_runtime_sha256()
            && m.seccomp_policy==*owner.seccomp_policy()
            && m.build_provenance.dependency_lock_sha256==*owner.dependency_lock_sha256()
            && m.build_provenance.build_recipe_sha256==*owner.build_recipe_sha256()
            && m.build_provenance.provenance_statement_sha256==*owner.provenance_sha256())
    }
}
impl PrekeyExecutable {
    pub(in crate::policy_shadow) fn from_late_owner(configuration:&Configuration,
        delivery:&PreparedGuestServiceDelivery,owner:&Retained)->Result<Self,ShadowError>{
        configuration.require_late_image(owner)?;
        let association=delivery.native_closure_association().map_err(unavailable)?;
        owner.require_guest(&association.binding())?;
        let executable=owner.executable()?;let identity=executable_identity(&executable)?;
        require(Sha256Digest::compute(&read(&executable,128*1024*1024)?)==configuration.manifest.worker_executable_sha256)?;
        let value=Self{executable,identity,association};value.check()?;Ok(value)
    }
}
impl PreparedNativeCustodyClosure {
    /// No root reopening, second drop, second filter install or inferred image.
    /// The same measured image/executable/filter survive the phase-two boundary.
    pub(in crate::policy_shadow) fn bind_late(configuration:Configuration,assignment:&VerifiedAssignment,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,delivery:&PreparedGuestServiceDelivery,
        owner:&Retained,prekey:&PrekeyExecutable)->Result<NativeCustodyClosureOwner,ShadowError>{
        owner.check_startup()?;configuration.require_late_image(owner)?;prekey.check()?;
        let association=delivery.native_closure_association().map_err(unavailable)?;
        owner.require_guest(&association.binding())?;
        require(association.same_origin(&prekey.association))?;
        revalidate_verified_freshness(assignment,trust,time,MAX_ENVELOPE_AGE_NANOS)?;
        let checkpoint=trust.current_checkpoint()?;let p=&configuration.authorization.payload;
        require(p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256)?;
        verify_assignment(&configuration.authorization,&configuration.manifest,&association.binding(),assignment,&checkpoint,trust)?;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        let image=owner.image();image.check(association.startup()).map_err(unavailable)?;
        check_root(&image)?;
        let executable=owner.executable()?;let executable_identity=executable_identity(&executable)?;
        require(executable_identity==prekey.identity && status_number("Threads:")?==1)?;
        require(read(image.executable(),128*1024*1024)?==read(&executable,128*1024*1024)?)?;
        check_current_executable(&executable_identity)?;
        let filters=owner.filter_count();require(status_number("Seccomp_filters:")?==filters)?;
        let prepared=Self{configuration,association,image,executable,executable_identity,checkpoint};
        let result=NativeCustodyClosureOwner(Arc::new(Core{prepared,filters,poisoned:AtomicBool::new(false)}));
        owner.check_startup()?;result.check()?;Ok(result)
    }
}
