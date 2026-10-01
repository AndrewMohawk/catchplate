//! Source-selected gate factory over actual retained native originals. The
//! receiving gate is not the measured bridge and never uses the host factory.
use super::super::*;
use crate::policy_shadow::policy_custody;
use super::services::{ConstructedDriver,NativeCustodyLifecycleOwner};
use native_custody_closure::RemoteNativeCustodyClosure;
use base64::Engine;
use super::production_dispatch::{ProductionGenerationInstallContextWireV4,
    ProductionGenerationInstallEnvelopeRoleV4};

fn ensure(value:bool)->Result<(),ShadowError>{if value{Ok(())}else{Err(ShadowError::BindingDrift)}}
fn exact<T:serde::de::DeserializeOwned+Serialize>(raw:&[u8])->Result<T,ShadowError>{
    let value:T=serde_json::from_slice(raw).map_err(|_|ShadowError::BindingDrift)?;
    ensure(canonical_json_bytes(&value)?==raw)?;Ok(value)
}
fn original<'a>(value:&'a serde_json::Value,name:&str)->Result<&'a [u8],ShadowError>{
    Ok(value.get(name).and_then(serde_json::Value::as_str).ok_or(ShadowError::BindingDrift)?.as_bytes())
}
fn digest(value:&serde_json::Value,name:&str)->Result<Sha256Digest,ShadowError>{
    serde_json::from_value(value.get(name).ok_or(ShadowError::BindingDrift)?.clone()).map_err(|_|ShadowError::BindingDrift)
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct EffectsSelection {
    api_version:String,head_grant_original:String,current_grant_original:String,origin_fd_name:String,cleanup_grant_original:String,
}
pub(in crate::policy_shadow) fn require_runtime(runtime:&serde_json::Value)->Result<(),ShadowError>{
    match runtime.get("apiVersion").and_then(serde_json::Value::as_str) {
        Some("serverware.policyCustodyProductionRpcRuntime/v5"|"serverware.policyCustodyProductionRpcRuntime/v6"
            |"serverware.policyCustodyProductionRpcRuntime/v7"|"serverware.policyCustodyProductionRpcRuntime/v8")=>Ok(()),
        Some("serverware.policyCustodyProductionRpcRuntime/v9"|"serverware.policyCustodyProductionRpcRuntime/v10"
            |"serverware.policyCustodyProductionRpcRuntime/v11")=>{
            if matches!(runtime.get("apiVersion").and_then(serde_json::Value::as_str),
                Some("serverware.policyCustodyProductionRpcRuntime/v10"|"serverware.policyCustodyProductionRpcRuntime/v11")) {
                super::services::production::validate_initial_history_runtime(&canonical_json_bytes(runtime)?)
                    .map_err(|_|ShadowError::BindingDrift)?;
            } else {
                ensure(runtime.get("ordinaryInitialHistories").is_none() && runtime.get("helperBootstrap").is_none())?;
            }
            // The actual measured bridge validates these independently signed
            // ordinary history grants. The receiving factory additionally pins
            // this exact successor, never a cleanup-less v3 projection.
            let value:EffectsSelection=serde_json::from_value(runtime.get("spool").ok_or(ShadowError::BindingDrift)?.clone())
                .map_err(|_|ShadowError::BindingDrift)?;
            ensure(value.api_version=="serverware.nativeSpoolServices/v3" && value.origin_fd_name=="generation-origin")?;
            for (raw,maximum,version) in [
                (value.head_grant_original.as_str(),65536,"serverware.nativeSpoolHeadGrant/v3"),
                (value.current_grant_original.as_str(),131072,"serverware.nativeSpoolCurrentGrant/v3"),
                (value.cleanup_grant_original.as_str(),131072,"serverware.nativeActiveEffectCleanupGrant/v1")] {
                ensure(raw.is_ascii() && !raw.is_empty() && raw.len()<=maximum)?;
                let grant:serde_json::Value=exact(raw.as_bytes())?;
                let object=grant.as_object().ok_or(ShadowError::BindingDrift)?;
                ensure(object.len()==2 && object.contains_key("payload") && object.contains_key("signatureBase64url")
                    && grant.get("payload").and_then(|v|v.get("apiVersion")).and_then(serde_json::Value::as_str)==Some(version))?;
            }
            Ok(())
        },
        _=>Err(ShadowError::BindingDrift),
    }
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow) struct Settings {
    pub(in crate::policy_shadow) signer_backend_sha256:Sha256Digest,
    pub(in crate::policy_shadow) persistence_backend_sha256:Sha256Digest,
    pub(in crate::policy_shadow) retrieval_backend_sha256:Sha256Digest,
    pub(in crate::policy_shadow) dispatcher_protocol_set_sha256:Sha256Digest,
    pub(in crate::policy_shadow) maximum_rpc_nanos:u64,
    pub(in crate::policy_shadow) cleanup_reserve_nanos:u64,
    pub(in crate::policy_shadow) maximum_in_flight_calls:u16,
    pub(in crate::policy_shadow) maximum_async_durability_nanos:u64,
    expected_configuration_binding_sha256:Sha256Digest,
}
/// Exact common scope from the retained, pinned ordinary grant originals.
/// These bytes do not create a service/root-key owner: the native bridge and
/// each ordinary service retain their existing complete grant admission.
#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct GenerationScope {
    previous_configuration_binding_sha256:Option<Sha256Digest>,
    successor_configuration_binding_sha256:Sha256Digest,
    dispatch_manifest_sha256:Sha256Digest,kernel_driver_identity_sha256:Sha256Digest,
    retained_descriptor_set_sha256:Sha256Digest,driver_generation_receipt_sha256:Sha256Digest,
    assignment_id:Sha256Digest,assignment_payload_sha256:Sha256Digest,assignment_revision:u64,
    operation_coverage_root_sha256:Sha256Digest,five_service_protocol_set_sha256:Sha256Digest,
    envelope_authority_key_id:Sha256Digest,envelope_authority_key_spki_sha256:Sha256Digest,
    trusted_time_checkpoint_sha256:Sha256Digest,trusted_time_revocation_generation:u64,
    trusted_time_revocation_root_sha256:Sha256Digest,
    installation_issued_at_unix_nanos:i64,installation_expires_at_unix_nanos:i64,
}
impl GenerationScope {
    fn context(&self,configuration:&ProductionCustodyConfiguration,manifest:&ProductionCustodyDispatchManifest,
        driver:&ProductionCustodyKernelDriverIdentity,receipt:&Sha256Digest,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<ProductionGenerationInstallContextWireV4,ShadowError>{
        let authority=configuration.authority_binding(AuthorityRole::CustodyResultEnvelope)?;
        let checkpoint=trust.current_checkpoint()?;
        ensure(&checkpoint==configuration.authority_trust_checkpoint()
            && self.successor_configuration_binding_sha256==*configuration.production_configuration_binding_sha256()
            && self.dispatch_manifest_sha256==*manifest.manifest_sha256()
            && self.kernel_driver_identity_sha256==*driver.identity_sha256()
            && self.retained_descriptor_set_sha256==driver.retained_descriptor_manifest_sha256
            && self.driver_generation_receipt_sha256==*receipt
            && self.assignment_id==*configuration.assignment_id()
            && self.assignment_payload_sha256==*configuration.assignment_payload_sha256()
            && self.assignment_revision==configuration.assignment_revision()
            && self.operation_coverage_root_sha256==*configuration.operation_coverage_root_sha256()
            && self.five_service_protocol_set_sha256==*configuration.dispatcher_protocol_set_sha256()
            && self.envelope_authority_key_id==*authority.key_id()
            && self.envelope_authority_key_spki_sha256==*authority.key_spki_sha256()
            && self.trusted_time_checkpoint_sha256==checkpoint.checkpoint_id
            && self.trusted_time_revocation_generation==checkpoint.revocation_generation
            && self.trusted_time_revocation_root_sha256==checkpoint.revocation_root_sha256
            && self.installation_issued_at_unix_nanos>0
            && self.installation_expires_at_unix_nanos.checked_sub(self.installation_issued_at_unix_nanos)
                .is_some_and(|duration|duration>0 && duration<=configuration.maximum_authority_evidence_age_nanos()))?;
        validate_trusted_freshness(self.installation_issued_at_unix_nanos,self.installation_expires_at_unix_nanos,
            time,configuration.maximum_authority_evidence_age_nanos())?;
        ensure(trust.current_checkpoint()?==checkpoint)?;
        Ok(ProductionGenerationInstallContextWireV4 {
            assignment_id:self.assignment_id.clone(),assignment_payload_sha256:self.assignment_payload_sha256.clone(),
            assignment_revision:self.assignment_revision,operation_coverage_root_sha256:self.operation_coverage_root_sha256.clone(),
            five_service_protocol_set_sha256:self.five_service_protocol_set_sha256.clone(),
            envelope_authority_role:ProductionGenerationInstallEnvelopeRoleV4::CustodyResultEnvelope,
            envelope_authority_key_id:self.envelope_authority_key_id.clone(),
            envelope_authority_key_spki_sha256:self.envelope_authority_key_spki_sha256.clone(),
            trusted_time_checkpoint_sha256:self.trusted_time_checkpoint_sha256.clone(),
            trusted_time_revocation_generation:self.trusted_time_revocation_generation,
            trusted_time_revocation_root_sha256:self.trusted_time_revocation_root_sha256.clone(),
            issued_at_unix_nanos:self.installation_issued_at_unix_nanos,
            expires_at_unix_nanos:self.installation_expires_at_unix_nanos,
        })
    }
}
pub(in crate::policy_shadow) struct Factory {
    pub(in crate::policy_shadow) configuration:ProductionCustodyConfiguration,
    pub(in crate::policy_shadow) manifest:ProductionCustodyDispatchManifest,
    pub(in crate::policy_shadow) driver:ProductionCustodyKernelDriverIdentity,
    pub(in crate::policy_shadow) prior_admission_sha256:Sha256Digest,
    pub(in crate::policy_shadow) settings:Settings,
    retained:Arc<ConstructedDriver>,
    installation_scope:GenerationScope,
    operation_boundary:u64,
}
impl Factory {
    pub(in crate::policy_shadow) fn open(owner:&Arc<NativeCustodyLifecycleOwner>,source:&Sha256Digest,
        assignment:VerifiedAssignment,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Self,ShadowError>{
        let retained=Arc::new(owner.constructed_driver(source,assignment.clone(),trust,time)?);
        let public:serde_json::Value=exact(retained.public_original())?;
        ensure(Sha256Digest::compute(original(&public,"assignmentOriginal")?)==*assignment.envelope_sha256())?;
        let closure=RemoteNativeCustodyClosure::admit(Arc::clone(&retained),&assignment,trust,time)?;
        let guest=closure.guest().clone();
        let phase:serde_json::Value=exact(original(&public,"phaseScopeOriginal")?)?;
        let payload=phase.get("payload").ok_or(ShadowError::BindingDrift)?;
        ensure(payload.get("apiVersion").and_then(serde_json::Value::as_str)==Some("serverware.nativeShadowDriverScope/v4"))?;
        let operation=payload.get("operation").ok_or(ShadowError::BindingDrift)?;
        ensure(operation.get("apiVersion").and_then(serde_json::Value::as_str)==Some("serverware.nativeShadowDriverOperation/v1"))?;
        let settings:Settings=serde_json::from_value(operation.get("production").ok_or(ShadowError::BindingDrift)?.clone())
            .map_err(|_|ShadowError::BindingDrift)?;
        let observed:serde_json::Value=exact(original(&public,"bootstrapObservationOriginal")?)?;
        let driver:ProductionCustodyKernelDriverIdentity=serde_json::from_value(observed.get("driver").ok_or(ShadowError::BindingDrift)?.clone())
            .map_err(|_|ShadowError::BindingDrift)?;
        let instance=Sha256Digest::compute(guest.invocation_id.as_bytes());
        let boot=Sha256Digest::compute(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&guest.boot_id_base64url)
            .map_err(|_|ShadowError::BindingDrift)?);
        closure.require_assignment(&assignment,trust,time,&instance,&boot)?;
        let configuration=ProductionCustodyConfiguration::from_retained_closure_with_settlement_authority(&assignment,trust,time,
            instance.clone(),boot.clone(),RetainedProductionCustodyClosure::RemoteNative(closure),
            settings.signer_backend_sha256.clone(),settings.persistence_backend_sha256.clone(),settings.retrieval_backend_sha256.clone(),
            settings.dispatcher_protocol_set_sha256.clone(),driver.clone(),settings.maximum_rpc_nanos,settings.cleanup_reserve_nanos,
            settings.maximum_in_flight_calls,settings.maximum_async_durability_nanos)?;
        ensure(configuration.production_configuration_binding_sha256()==&settings.expected_configuration_binding_sha256)?;
        let configuration=policy_custody::services::guest::native_keys::admission::remote::activate(
            retained.public_original(),configuration,&assignment,&guest,trust,time)?;
        // This is the genuinely same parent named in BOTH the pre-grant signed
        // bootstrap admission and the later complete constructed census.
        let census:serde_json::Value=exact(retained.census_original())?;
        let parent=census.get("parent").ok_or(ShadowError::BindingDrift)?;
        let start=parent.get("startTimeTicks").and_then(serde_json::Value::as_u64).ok_or(ShadowError::BindingDrift)?;
        let mut reaper=ProductionCustodyStableReaperIdentity{
            reaper_instance_sha256:hash_domain_frames(b"serverware.nativeShadowStableParentInstance/v1",
                &[&canonical_json_bytes(&(parent,&instance))?]),
            reaper_executable_sha256:digest(&census,"parentExecutableSha256")?,supervisor_instance_sha256:instance,
            supervisor_boot_id_sha256:boot,kernel_driver_identity_sha256:driver.identity_sha256().clone(),
            subreaper_process_start_time_ticks:start,pidfd_namespace_sha256:digest(&census,"pidNamespaceSha256")?,
            // Preserve the original driver's actual bootstrap descriptor scope.
            // Complete operational coverage is REQUIRED by retained, separately.
            retained_descriptor_set_sha256:driver.retained_descriptor_manifest_sha256.clone(),ownership_epoch:start,
            independent_restart_forbidden:true,identity_sha256:Sha256Digest::compute(&[])};
        reaper.identity_sha256=hash_domain_frames(b"serverware.policyShadowCustodyStableReaper/v1",&[&canonical_json_bytes(&(
            &reaper.reaper_instance_sha256,&reaper.reaper_executable_sha256,&reaper.supervisor_instance_sha256,
            &reaper.supervisor_boot_id_sha256,&reaper.kernel_driver_identity_sha256,reaper.subreaper_process_start_time_ticks,
            &reaper.pidfd_namespace_sha256,&reaper.retained_descriptor_set_sha256,reaper.ownership_epoch,reaper.independent_restart_forbidden))?]);
        let manifest=ProductionCustodyDispatchManifest::from_verified_external_dispatcher(&configuration,driver.clone(),reaper,
            settings.dispatcher_protocol_set_sha256.clone(),8*1024*1024,8*1024*1024,settings.maximum_async_durability_nanos)?;
        let bundle:serde_json::Value=exact(original(&public,"phaseBundleOriginal")?)?;
        let runtime_raw=original(&bundle,"runtimeOriginal")?;
        ensure(Sha256Digest::compute(runtime_raw)==guest.runtime_configuration_sha256)?;
        let runtime:serde_json::Value=exact(runtime_raw)?;
        require_runtime(&runtime)?;
        let pins=runtime.get("generationAdmission").and_then(|v|v.get("grants")).and_then(serde_json::Value::as_object).ok_or(ShadowError::BindingDrift)?;
        let grants=bundle.get("generationOriginals").and_then(serde_json::Value::as_object).ok_or(ShadowError::BindingDrift)?;
        ensure(pins.len()==5 && grants.len()==5 && pins.keys().eq(grants.keys()))?;
        let roles=["durable-recovery-store","cleanup-authorization-consumer","recovery-target-provider",
            "current-signature-authority","bounded-cleanup-helper"];
        ensure(roles.iter().all(|role|grants.contains_key(*role)))?;
        let mut installation_scope:Option<GenerationScope>=None;
        for (role,raw) in grants {
            let raw=raw.as_str().ok_or(ShadowError::BindingDrift)?.as_bytes();
            ensure(!raw.is_empty() && raw.len()<=65536 && raw.is_ascii())?;
            ensure(pins.get(role)==Some(&serde_json::to_value(Sha256Digest::compute(raw)).map_err(|_|ShadowError::BindingDrift)?))?;
            let grant:serde_json::Value=exact(raw)?;
            let payload=grant.get("payload").ok_or(ShadowError::BindingDrift)?;
            ensure(payload.get("apiVersion").and_then(serde_json::Value::as_str)==Some("serverware.custodyServiceGenerationGrant/v1")
                && payload.get("purpose").and_then(serde_json::Value::as_str)==Some("cold-service-generation-admission")
                && payload.get("serviceRole").and_then(serde_json::Value::as_str)==Some(role.as_str()))?;
            let scope:GenerationScope=exact(&canonical_json_bytes(payload.get("scope").ok_or(ShadowError::BindingDrift)?)?)?;
            if let Some(expected)=&installation_scope {ensure(expected==&scope)?;}
            else {installation_scope=Some(scope);}
        }
        let installation_scope=installation_scope.ok_or(ShadowError::BindingDrift)?;
        ensure(assignment.payload().issued_at_unix_nanos()<=installation_scope.installation_issued_at_unix_nanos
            && installation_scope.installation_expires_at_unix_nanos<=assignment.payload().expires_at_unix_nanos())?;
        retained.check(trust,time)?;
        installation_scope.context(&configuration,&manifest,&driver,retained.bootstrap_admission_sha256(),trust,time)?;
        let lifetime=guest.lifetime_deadline_boottime_ns.parse::<u64>().map_err(|_|ShadowError::BindingDrift)?;
        let operation_boundary=lifetime.checked_sub(settings.cleanup_reserve_nanos).ok_or(ShadowError::BindingDrift)?;
        Ok(Self{configuration,manifest,driver,prior_admission_sha256:retained.bootstrap_admission_sha256().clone(),
            settings,retained,installation_scope,operation_boundary})
    }
    pub(in crate::policy_shadow) fn check(&self,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        self.retained.check(trust,time)?;
        self.configuration.revalidate_active_attestation(trust,time)?;
        Ok(())
    }
    pub(in crate::policy_shadow) fn generation_install_context(&self,previous:Option<&ProductionCustodyConfiguration>,
        successor:&ProductionCustodyConfiguration,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<ProductionGenerationInstallContextWireV4,ShadowError>{
        self.check(trust,time)?;
        successor.revalidate_active_attestation(trust,time)?;
        ensure(previous.map(|value|value.production_configuration_binding_sha256())
            ==self.installation_scope.previous_configuration_binding_sha256.as_ref())?;
        self.check(trust,time)?;
        self.installation_scope.context(successor,&self.manifest,&self.driver,&self.prior_admission_sha256,trust,time)
    }
    pub(super) fn take_sessions(&self)->Result<Vec<policy_custody::services::common::AuthenticatedInheritedSeqpacket>,ShadowError>{
        self.retained.take_sessions()
    }
    pub(super) fn require_deadline(&self,deadline:u64)->Result<u64,ShadowError>{
        self.retained.check_live()?;
        ensure(policy_custody::boottime::boottime_now_nanos().map_err(|_|ShadowError::CustodyUnavailable)?<deadline
            && deadline<=self.operation_boundary)?;Ok(deadline)
    }
}
