//! Explicit cold coordinator successor: the immutable image contains only a
//! fixed measured bootstrap. The genuine C9 owner retains the complete later
//! runtime, and the closure signature binds its entire actual guest value.
//! No bridge role, excluded signature field, or caller-selected pin is used.
use super::*;

const COORDINATOR:&str="publicationGenesisCoordinator";
const BOOTSTRAP_API:&str="serverware.nativePublicationGenesisBootstrapRuntime/v1";
const BOOTSTRAP_PURPOSE:&str="measure-publication-genesis-before-runtime-admission";
const MAX_BOOTSTRAP:u64=4096;

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Bootstrap {api_version:String,purpose:String}

pub(super) fn require_bootstrap(raw:&[u8],measured:&Sha256Digest,complete:&Sha256Digest)->Result<(),ShadowError>{
    require(!raw.is_empty() && raw.len()<=MAX_BOOTSTRAP as usize && raw.is_ascii() && measured!=complete)?;
    let value:Bootstrap=serde_json::from_slice(raw).map_err(unavailable)?;
    require(value.api_version==BOOTSTRAP_API && value.purpose==BOOTSTRAP_PURPOSE
        && canonical_json_bytes(&value)?==raw && Sha256Digest::compute(raw)==*measured)
}

impl Configuration {
    /// The launch version, never the supplied role string, selects this API.
    /// The old cold coordinator remains exactly Closure/v4 + static Manifest/v1.
    pub(in crate::policy_shadow) fn require_genesis_selection(&self,late:bool)->Result<(),ShadowError>{
        require(self.api_version==(if late{"serverware.nativeCustodyClosure/v6"}else{"serverware.nativeCustodyClosure/v4"}))?;
        self.require_selected_profile(Some(COORDINATOR),false,late)?;
        Ok(())
    }
    pub(super) fn require_genesis_guest(&self,guest:&GuestClosureBinding)->Result<(),ShadowError>{
        self.require_genesis_selection(true)?;
        require(&self.authorization.payload.guest==guest
            && guest.runtime_configuration_sha256!=self.manifest.runtime_configuration_sha256)
    }
    pub(in crate::policy_shadow) fn require_genesis_pair_image(&self,image:&Sha256Digest,executable:&Sha256Digest)
        ->Result<(),ShadowError>{
        self.require_genesis_selection(true)?;
        require(&self.manifest.image_sha256==image && &self.manifest.worker_executable_sha256==executable)
    }
    pub(in crate::policy_shadow) fn prepare_genesis_parent_image(&self,
        delivery:&policy_custody::services::guest::FileAdmission)->Result<ShadowImage,ShadowError>{
        delivery.check_preparation().map_err(unavailable)?;
        self.require_genesis_selection(true)?;
        let m=&self.manifest;let b=&m.build_provenance;
        require(&self.authorization.payload.guest.runtime_configuration_sha256==delivery.runtime_sha256())?;
        let image=ShadowImage::open(m.image_sha256.as_str(),m.worker_executable_sha256.as_str(),[
            m.seccomp_policy.raw_bpf_sha256().as_str(),m.runtime_configuration_sha256.as_str(),
            b.dependency_lock_sha256.as_str(),b.build_recipe_sha256.as_str(),b.provenance_statement_sha256.as_str()],
            delivery.startup()).map_err(unavailable)?;
        require_bootstrap(&read(image.configuration(),MAX_BOOTSTRAP)?,&m.runtime_configuration_sha256,delivery.runtime_sha256())?;
        require(read(image.seccomp(),32768)?==custody_seccomp_raw_bytes(m.seccomp_policy.exact_instructions()))?;
        delivery.check_preparation().map_err(unavailable)?;
        Ok(image)
    }
}

impl PrekeyExecutable {
    pub(in crate::policy_shadow) fn open_genesis(configuration:&Configuration,delivery:&PreparedGuestServiceDelivery)
        ->Result<Self,ShadowError>{
        Self::open_selected(configuration,delivery,Some(COORDINATOR),true)
    }
}
impl PreparedNativeCustodyClosure {
    pub(in crate::policy_shadow) fn open_genesis(configuration:Configuration,assignment:&VerifiedAssignment,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,delivery:&PreparedGuestServiceDelivery)
        ->Result<Self,ShadowError>{
        Self::open_selected(configuration,assignment,trust,time,delivery,Some(COORDINATOR),true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn original()->Vec<u8>{canonical_json_bytes(&Bootstrap{api_version:BOOTSTRAP_API.into(),purpose:BOOTSTRAP_PURPOSE.into()}).unwrap()}

    #[test]
    fn measured_bootstrap_is_distinct_from_complete_runtime(){
        let raw=original();let pin=Sha256Digest::compute(&raw);
        assert!(require_bootstrap(&raw,&pin,&Sha256Digest::compute(b"complete-runtime")).is_ok());
        assert!(require_bootstrap(&raw,&pin,&pin).is_err());
        assert!(require_bootstrap(&raw,&Sha256Digest::compute(b"wrong-pin"),&Sha256Digest::compute(b"complete-runtime")).is_err());
    }
    #[test]
    fn measured_bootstrap_rejects_late_or_unknown_fields(){
        let raw=original();let mut value:serde_json::Value=serde_json::from_slice(&raw).unwrap();
        value.as_object_mut().unwrap().insert("assignmentPayloadSha256".into(),serde_json::Value::String(Sha256Digest::compute(b"assignment").as_str().to_owned()));
        let extra=canonical_json_bytes(&value).unwrap();
        assert!(require_bootstrap(&extra,&Sha256Digest::compute(&extra),&Sha256Digest::compute(b"runtime")).is_err());
        let mut newline=raw;newline.push(b'\n');
        assert!(require_bootstrap(&newline,&Sha256Digest::compute(&newline),&Sha256Digest::compute(b"runtime")).is_err());
    }
    #[test]
    fn measured_bootstrap_requires_exact_api_and_purpose(){
        for (api,purpose) in [("serverware.nativePublicationGenesisCoordinatorRuntime/v2",BOOTSTRAP_PURPOSE),(BOOTSTRAP_API,"measure-bridge")] {
            let raw=canonical_json_bytes(&Bootstrap{api_version:api.into(),purpose:purpose.into()}).unwrap();
            assert!(require_bootstrap(&raw,&Sha256Digest::compute(&raw),&Sha256Digest::compute(b"runtime")).is_err());
        }
    }
}
