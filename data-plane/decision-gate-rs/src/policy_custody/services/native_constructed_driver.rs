//! Independently verified constructed-driver admission. This is intentionally
//! not a native configuration, an installed generation, or a settled reaper.
use super::*;
use crate::policy_shadow::{VerifiedAssignment,EnvelopeKeyTrust,TrustedTime,ShadowError,AuthorityRole,
    AtomicTrustCheckpoint,MAX_ENVELOPE_AGE_NANOS,authority_role_signature_domain,
    revalidate_verified_freshness,revalidate_verified_at_checkpoint,verify_assignment_authority_key_material_at_checkpoint,
    validate_trusted_freshness,ed25519_public_key_material_sha256,signature_preimage,canonical_json_bytes};

pub(in crate::policy_shadow) struct ConstructedDriver {
    owner:Arc<Owner>,source:Sha256Digest,original:Vec<u8>,census:Vec<u8>,public:Vec<u8>,
    grant:wire::ConstructedAdmission,assignment:VerifiedAssignment,
}
fn error<T>(_:T)->ShadowError{ShadowError::CustodyUnavailable}
fn ensure(value:bool)->Result<(),ShadowError>{if value{Ok(())}else{Err(ShadowError::BindingDrift)}}
fn verify(grant:&wire::ConstructedAdmission,assignment:&VerifiedAssignment,trust:&dyn EnvelopeKeyTrust,
    time:&dyn TrustedTime)->Result<AtomicTrustCheckpoint,ShadowError>{
    let checkpoint=trust.current_checkpoint()?;let p=&grant.payload;
    revalidate_verified_freshness(assignment,trust,time,MAX_ENVELOPE_AGE_NANOS)?;
    validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,30_000_000_000)?;
    verify_at(grant,assignment,&checkpoint,trust)?;Ok(checkpoint)
}
fn verify_at(grant:&wire::ConstructedAdmission,assignment:&VerifiedAssignment,checkpoint:&AtomicTrustCheckpoint,
    trust:&dyn EnvelopeKeyTrust)->Result<(),ShadowError>{
    let p=&grant.payload;let a=assignment.payload();
    revalidate_verified_at_checkpoint(assignment,&checkpoint,trust,MAX_ENVELOPE_AGE_NANOS)?;
    verify_assignment_authority_key_material_at_checkpoint(assignment,&checkpoint,trust)?;
    ensure(p.api_version=="catchplate.nativeShadowConstructedDriverAdmission/v1" && p.purpose=="constructed-native-driver-admission"
        && p.assignment_id==a.assignment_id && &p.assignment_payload_sha256==assignment.payload_sha256()
        && p.assignment_revision==a.assignment_revision && p.trust_checkpoint_id==checkpoint.checkpoint_id
        && p.revocation_generation==checkpoint.revocation_generation && p.revocation_root_sha256==checkpoint.revocation_root_sha256)?;
    let binding=a.authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,&a.assignment_id)?;
    ensure(p.signing_key_id==binding.key_id && p.signing_key_spki_sha256==binding.key_spki_sha256)?;
    let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),
        &binding.key_id,&binding.key_spki_sha256)?;
    ensure(ed25519_public_key_material_sha256(&key)==binding.key_material_sha256)?;
    key.verify_strict(&signature_preimage(wire::CONSTRUCTED_DOMAIN,&canonical_json_bytes(p)?),
        &ed25519_dalek::Signature::from_bytes(&grant.signature.decode()?)).map_err(|_|ShadowError::SignatureInvalid)?;
    ensure(grant.bootstrap_admission_original.len()<=8192 && grant.bootstrap_admission_original.is_ascii()
        && p.bootstrap_admission_sha256==Sha256Digest::compute(grant.bootstrap_admission_original.as_bytes()))?;
    let early:wire::BootstrapAdmission=exact(grant.bootstrap_admission_original.as_bytes()).map_err(error)?;let e=&early.payload;
    key.verify_strict(&signature_preimage(wire::BOOTSTRAP_ADMISSION_DOMAIN,&canonical_json_bytes(e)?),
        &ed25519_dalek::Signature::from_bytes(&early.signature.decode()?)).map_err(|_|ShadowError::SignatureInvalid)?;
    ensure(e.api_version=="catchplate.nativeShadowBootstrapDriverAdmission/v1" && e.purpose=="native-driver-bootstrap-admission"
        && e.signing_key_id==binding.key_id && e.signing_key_spki_sha256==binding.key_spki_sha256
        && e.configuration_sha256==p.configuration_sha256 && e.window_sha256==p.window_sha256
        && Sha256Digest::compute(e.bootstrap_observation_original.as_bytes())==p.bootstrap_observation_sha256
        && e.startup_deadline_boottime_ns==p.startup_deadline_boottime_ns && e.lifetime_deadline_boottime_ns==p.lifetime_deadline_boottime_ns
        && e.issued_at_unix_nanos<=p.issued_at_unix_nanos && p.issued_at_unix_nanos<p.expires_at_unix_nanos
        && p.expires_at_unix_nanos<=e.expires_at_unix_nanos
        && e.expires_at_unix_nanos.checked_sub(e.issued_at_unix_nanos).is_some_and(|v|v>0 && v<=30_000_000_000))?;
    ensure(trust.current_checkpoint()?==*checkpoint)
}
impl Owner {
    pub(in crate::policy_shadow) fn constructed_driver(self:&Arc<Self>,source:&Sha256Digest,assignment:VerifiedAssignment,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<ConstructedDriver,ShadowError>{
        self.check(source).map_err(error)?;
        let public=self.public_admission_original(source).map_err(error)?;
        let (original,census,prepared,startup,lifetime,configuration,window,bootstrap)={
            let mut channel=self.channel.try_lock().map_err(error)?;
            ensure(channel.configuration.api_version=="catchplate.nativeShadowCustodyLifecycleReceiver/v3")?;
            let startup=channel.startup;
            let census=channel.exchange("constructed-census",startup).map_err(error)?;
            let original=channel.exchange("constructed-admission",startup).map_err(error)?;
            channel.failed=true;
            (original,census,channel.prepared_original.clone(),startup,channel.lifetime,
                channel.configuration.driver_configuration_sha256.clone(),channel.configuration.driver_window_sha256.clone(),
                channel.configuration.bootstrap_observation_sha256.clone())
        };
        ensure(original.len()<=16384 && census.len()<=48*1024)?;
        let grant:wire::ConstructedAdmission=exact(&original).map_err(error)?;
        verify(&grant,&assignment,trust,time)?;
        let observation:wire::Observation=exact(&census).map_err(error)?;
        let prepared:wire::PreparedOriginal=exact(&prepared).map_err(error)?;
        let admission:wire::PublicAdmission=exact(&public).map_err(error)?;
        let bootstrap_original:serde_json::Value=exact(admission.bootstrap_observation_original.as_bytes()).map_err(error)?;
        let evidence:serde_json::Value=exact(admission.evidence_original.as_bytes()).map_err(error)?;
        let statement=evidence.get("statement").ok_or(ShadowError::BindingDrift)?;
        let digest=|value:&serde_json::Value,name:&str|->Result<Sha256Digest,ShadowError>{
            serde_json::from_value(value.get(name).ok_or(ShadowError::BindingDrift)?.clone()).map_err(error)};
        let p=&grant.payload;
        let early:wire::BootstrapAdmission=exact(grant.bootstrap_admission_original.as_bytes()).map_err(error)?;
        ensure(admission.api_version=="catchplate.nativeShadowDriverPublicAdmission/v1"
            && observation.api_version=="catchplate.nativeShadowDriverLifecycleObservation/v1"
            && observation.phase=="constructed-driver-subtree" && observation.parent==prepared.parent
            && observation.parent_executable_sha256==prepared.parent_executable_sha256
            && observation.pid_namespace_sha256==prepared.pid_namespace_sha256
            && early.payload.parent==observation.parent && early.payload.parent_executable_sha256==observation.parent_executable_sha256
            && early.payload.pid_namespace_sha256==observation.pid_namespace_sha256
            && observation.configuration_sha256==configuration && observation.window_sha256==window
            && observation.bootstrap_observation_sha256==bootstrap && observation.lifetime_deadline_boottime_ns==prepared.lifetime_deadline_boottime_ns
            && observation.scope_sha256==Sha256Digest::compute(admission.phase_scope_original.as_bytes())
            && p.configuration_sha256==configuration && p.window_sha256==window && p.bootstrap_observation_sha256==bootstrap
            && p.phase_scope_sha256==observation.scope_sha256 && p.census_sha256==Sha256Digest::compute(&census)
            && p.public_admission_sha256==Sha256Digest::compute(&public) && p.startup_deadline_boottime_ns==startup.to_string()
            && p.lifetime_deadline_boottime_ns==prepared.lifetime_deadline_boottime_ns
            && ns(&p.lifetime_deadline_boottime_ns).map_err(error)?>lifetime
            && bootstrap==Sha256Digest::compute(admission.bootstrap_observation_original.as_bytes())
            && p.kernel_driver_identity_sha256==digest(bootstrap_original.get("driver").ok_or(ShadowError::BindingDrift)?,"identitySha256")?
            && p.production_configuration_binding_sha256==digest(statement,"productionConfigurationBindingSha256")?
            && observation.driver.process_id==bootstrap_original.get("processId").and_then(serde_json::Value::as_i64).ok_or(ShadowError::BindingDrift)? as i32
            && observation.driver.parent_id==observation.parent.process_id
            && !observation.descendants.is_empty() && observation.descendants.len()<=16
            && observation.descendants.iter().any(|v|v==&observation.driver)
            && observation.descendants.windows(2).all(|v|v[0].process_id<v[1].process_id)
            && !observation.descriptors.is_empty() && observation.descriptors.len()<=256
            && observation.descriptors.windows(2).all(|v|v[0].fd<v[1].fd)
            && observation.descriptor_set_sha256==Sha256Digest::compute(&canonical_json_bytes(&observation.descriptors)?)
            && ns(&observation.observed_at_boottime_ns).map_err(error)?<=now().map_err(error)?
            && ns(&observation.observed_at_boottime_ns).map_err(error)?<startup
            && now().map_err(error)?<startup)?;
        let context=statement.get("nativeContext").ok_or(ShadowError::BindingDrift)?;
        let root=bootstrap_original.get("root").ok_or(ShadowError::BindingDrift)?;
        ensure(context.get("apiVersion").and_then(serde_json::Value::as_str)==Some("catchplate.nativeShadowKeyAdmissionContext/v1")
            && context.get("profile").and_then(serde_json::Value::as_str)==Some("same-process-native-originals-v1")
            && digest(context,"guestSha256")?==Sha256Digest::compute(&canonical_json_bytes(statement.get("guest").ok_or(ShadowError::BindingDrift)?)?)
            && digest(context,"executionClosureManifestSha256")?==digest(statement,"executionClosureManifestSha256")?
            && digest(context,"cgroupSha256")?==digest(&bootstrap_original,"cgroupOriginalSha256")?
            && context.get("rootDevice").and_then(serde_json::Value::as_u64)
                ==Some(root.get("device").and_then(serde_json::Value::as_u64).ok_or(ShadowError::BindingDrift)?)
            && context.get("rootInode").and_then(serde_json::Value::as_u64)
                ==Some(root.get("inode").and_then(serde_json::Value::as_u64).filter(|v|*v>0).ok_or(ShadowError::BindingDrift)?)
            && ns(context.get("observedAtBoottimeNs").and_then(serde_json::Value::as_str).ok_or(ShadowError::BindingDrift)?).map_err(error)?<=startup
            && context.get("processId").and_then(serde_json::Value::as_i64)==Some(i64::from(observation.driver.process_id))
            && context.get("processStartTicks").and_then(serde_json::Value::as_u64)==Some(observation.driver.start_time_ticks)
            && context.get("pidfdInode").and_then(serde_json::Value::as_u64)==Some(observation.driver.pidfd_inode)
            && context.get("parentProcessId").and_then(serde_json::Value::as_i64)==Some(i64::from(observation.parent.process_id))
            && context.get("parentStartTicks").and_then(serde_json::Value::as_u64)==Some(observation.parent.start_time_ticks)
            && context.get("parentPidfdInode").and_then(serde_json::Value::as_u64)==Some(observation.parent.pidfd_inode))?;
        let bootstrap_descriptors=bootstrap_original.get("descriptors").and_then(serde_json::Value::as_array).ok_or(ShadowError::BindingDrift)?;
        ensure(bootstrap_descriptors.len()==4)?;
        for expected in bootstrap_descriptors {
            ensure(observation.descriptors.iter().any(|actual|
                expected.get("device").and_then(serde_json::Value::as_u64)==Some(actual.device)
                && expected.get("inode").and_then(serde_json::Value::as_u64)==Some(actual.inode)
                && expected.get("mode").and_then(serde_json::Value::as_u64)==Some(u64::from(actual.mode))
                && expected.get("mountId").and_then(serde_json::Value::as_u64)==Some(actual.mount_id)))?;
        }
        {let mut channel=self.channel.try_lock().map_err(error)?;channel.failed=false;channel.live(startup).map_err(error)?;}
        self.check(source).map_err(error)?;
        Ok(ConstructedDriver{owner:Arc::clone(self),source:source.clone(),original,census,public,grant,assignment})
    }
}
impl ConstructedDriver {
    pub(in crate::policy_shadow) fn check_live(&self)->Result<(),ShadowError>{
        self.owner.check(&self.source).map_err(error)?;
        let mut channel=self.owner.channel.try_lock().map_err(error)?;let deadline=channel.lifetime;
        let raw=channel.exchange("constructed-live",deadline).map_err(error)?;channel.failed=true;
        ensure(raw==canonical_json_bytes(&serde_json::json!({"apiVersion":"catchplate.nativeShadowConstructedDriverLive/v1",
            "admissionSha256":Sha256Digest::compute(&self.original),"censusSha256":Sha256Digest::compute(&self.census)}))?)?;
        channel.failed=false;channel.live(deadline).map_err(error)
    }
    pub(in crate::policy_shadow::policy_custody) fn take_sessions(&self)->Result<Vec<common::AuthenticatedInheritedSeqpacket>,ShadowError>{
        self.check_live()?;self.owner.take_facade_sessions(&self.source).map_err(error)
    }
    pub(in crate::policy_shadow) fn verify_current(&self,checkpoint:&AtomicTrustCheckpoint,trust:&dyn EnvelopeKeyTrust)->Result<(),ShadowError>{
        self.check_live()?;verify_at(&self.grant,&self.assignment,checkpoint,trust)
    }
    pub(in crate::policy_shadow) fn freshness(&self,now:i64)->Result<(),ShadowError>{
        self.check_live()?;crate::policy_shadow::validate_freshness(self.grant.payload.issued_at_unix_nanos,
            self.grant.payload.expires_at_unix_nanos,now,30_000_000_000)
    }
    pub(in crate::policy_shadow) fn check(&self,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        self.check_live()?;verify(&self.grant,&self.assignment,trust,time)?;
        ensure(self.owner.public_admission_original(&self.source).map_err(error)?==self.public)
    }
    pub(in crate::policy_shadow) fn admission_original(&self)->&[u8]{&self.original}
    pub(in crate::policy_shadow) fn census_original(&self)->&[u8]{&self.census}
    pub(in crate::policy_shadow) fn public_original(&self)->&[u8]{&self.public}
    pub(in crate::policy_shadow) fn bootstrap_admission_sha256(&self)->&Sha256Digest{&self.grant.payload.bootstrap_admission_sha256}
}
