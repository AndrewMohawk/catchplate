//! Receiving-side closure: signed originals plus the actual retained remote
//! lifecycle. It never claims the gate is the locally measured bridge process.
use super::*;
use policy_custody::services::ConstructedDriver;

struct Core {driver:Arc<ConstructedDriver>,configuration:Configuration,guest:GuestClosureBinding,
    assignment:VerifiedAssignment,membership:Option<Membership>}
#[derive(Clone)]
pub(in crate::policy_shadow) struct RemoteNativeCustodyClosure(Arc<Core>);
impl std::fmt::Debug for RemoteNativeCustodyClosure {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.debug_struct("RemoteNativeCustodyClosure")
        .field("manifest_sha256",&self.0.configuration.manifest.manifest_sha256).finish_non_exhaustive()}
}
impl PartialEq for RemoteNativeCustodyClosure {fn eq(&self,other:&Self)->bool{Arc::ptr_eq(&self.0,&other.0)}}
impl Eq for RemoteNativeCustodyClosure {}
fn exact<T:serde::de::DeserializeOwned+Serialize>(raw:&[u8])->Result<T,ShadowError>{
    let value:T=serde_json::from_slice(raw).map_err(unavailable)?;require(canonical_json_bytes(&value)?==raw)?;Ok(value)
}
impl RemoteNativeCustodyClosure {
    pub(in crate::policy_shadow) fn key_membership(&self)->Result<Option<KeyMembership>,ShadowError>{
        self.check()?;
        Ok(self.0.membership.as_ref().map(|member|KeyMembership::from_admitted(
            &self.0.configuration,member,self.0.guest.clone())))
    }
    pub(in crate::policy_shadow) fn admit(driver:Arc<ConstructedDriver>,assignment:&VerifiedAssignment,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Self,ShadowError>{
        driver.check(trust,time)?;
        // The wire was admitted only through the live receiver's sealed FD.
        let public:serde_json::Value=exact(driver.public_original())?;
        let original=public.get("closureOriginal").and_then(serde_json::Value::as_str).ok_or(ShadowError::BindingDrift)?;
        require(!original.is_empty() && original.len()<=1024*1024)?;
        let configuration:Configuration=exact(original.as_bytes())?;
        let keys:serde_json::Value=exact(public.get("keyConfigurationOriginal").and_then(serde_json::Value::as_str)
            .ok_or(ShadowError::BindingDrift)?.as_bytes())?;
        let guest:GuestClosureBinding=serde_json::from_value(keys.get("authorization").and_then(|v|v.get("payload"))
            .and_then(|v|v.get("guest")).ok_or(ShadowError::BindingDrift)?.clone()).map_err(unavailable)?;
        // This receiver is the retained constructed bridge, never an endpoint
        // selected by the closure document's own role string.
        let membership=configuration.require_profile(Some("bridge"),true)?;
        let value=Self(Arc::new(Core{driver,configuration,guest,assignment:assignment.clone(),membership}));
        value.verify_current(&trust.current_checkpoint()?,trust)?;value.freshness(time.now_unix_nanos()?)?;Ok(value)
    }
    pub(in crate::policy_shadow) fn check(&self)->Result<(),ShadowError>{
        self.0.driver.check_live()?;self.0.configuration.manifest.validate()
    }
    pub(in crate::policy_shadow) fn verify_current(&self,checkpoint:&AtomicTrustCheckpoint,trust:&dyn EnvelopeKeyTrust)->Result<(),ShadowError>{
        self.check()?;let p=&self.0.configuration.authorization.payload;
        self.0.driver.verify_current(checkpoint,trust)?;
        require(p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256)?;
        verify_assignment(&self.0.configuration.authorization,&self.0.configuration.manifest,&self.0.guest,
            &self.0.assignment,checkpoint,trust,self.0.membership.as_ref())
    }
    pub(in crate::policy_shadow) fn freshness(&self,now:i64)->Result<(),ShadowError>{
        self.check()?;let p=&self.0.configuration.authorization.payload;
        self.0.driver.freshness(now)?;
        validate_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,now,MAX_ENVELOPE_AGE_NANOS)
    }
    pub(in crate::policy_shadow) fn require_assignment(&self,assignment:&VerifiedAssignment,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,
        instance:&Sha256Digest,boot:&Sha256Digest)->Result<(),ShadowError>{
        self.0.driver.check(trust,time)?;
        require(assignment.payload_sha256()==self.0.assignment.payload_sha256()
            && instance==&Sha256Digest::compute(self.0.guest.invocation_id.as_bytes()))?;
        use base64::Engine;
        let raw=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&self.0.guest.boot_id_base64url).map_err(unavailable)?;
        require(raw.len()==16 && &Sha256Digest::compute(&raw)==boot)?;
        self.verify_current(&trust.current_checkpoint()?,trust)?;self.freshness(time.now_unix_nanos()?)
    }
    pub(in crate::policy_shadow) fn manifest_sha256(&self)->&Sha256Digest{&self.0.configuration.manifest.manifest_sha256}
    pub(in crate::policy_shadow) fn seccomp_policy_sha256(&self)->&Sha256Digest{self.0.configuration.manifest.seccomp_policy.policy_sha256()}
    pub(in crate::policy_shadow) fn worker_executable_sha256(&self)->&Sha256Digest{&self.0.configuration.manifest.worker_executable_sha256}
    pub(in crate::policy_shadow) fn native_closure_set(&self)->Option<&NativeClosureSetCommitment>{
        self.0.membership.as_ref().map(|member|&member.commitment)
    }
    pub(in crate::policy_shadow) fn native_closure_set_role(&self)->Option<&str>{
        self.0.membership.as_ref().map(|member|member.role)
    }
    pub(in crate::policy_shadow) fn guest(&self)->&GuestClosureBinding{&self.0.guest}
    pub(in crate::policy_shadow) fn driver(&self)->&Arc<ConstructedDriver>{&self.0.driver}
    pub(in crate::policy_shadow) fn request_facts_selected(&self)->Result<bool,ShadowError>{
        self.check()?;
        let public:serde_json::Value=exact(self.0.driver.public_original())?;
        let bundle:serde_json::Value=exact(public.get("phaseBundleOriginal").and_then(serde_json::Value::as_str)
            .ok_or(ShadowError::BindingDrift)?.as_bytes())?;
        let raw=bundle.get("runtimeOriginal").and_then(serde_json::Value::as_str).ok_or(ShadowError::BindingDrift)?;
        require(Sha256Digest::compute(raw.as_bytes())==self.0.guest.runtime_configuration_sha256)?;
        let runtime:serde_json::Value=exact(raw.as_bytes())?;
        if matches!(runtime.get("apiVersion").and_then(serde_json::Value::as_str),
            Some("serverware.policyCustodyProductionRpcRuntime/v10"|"serverware.policyCustodyProductionRpcRuntime/v11")) {
            policy_custody::native_remote_factory::require_runtime(&runtime)?;
            return Ok(true);
        }
        Ok(runtime.get("apiVersion").and_then(serde_json::Value::as_str)==Some("serverware.policyCustodyProductionRpcRuntime/v9"))
    }
}
