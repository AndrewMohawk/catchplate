//! Native request verification plus one actual custody contact. This does not
//! convert controlled readiness into Fleet authority or mutate the CP head.
use super::*;
use super::super::policy_shadow::native_activation as operation;
use serverware_decision_gate::{native_policy_activation_transport as transport,native_serving_privileges};
pub(crate) const PATH:&str="/v1/policy-shadow/native-activations";
pub(crate) const MAX_BODY_BYTES:u64=8*1024*1024;
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Configuration{api_version:String,authority:AuthorityPin,channel:transport::Configuration}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct AuthorityPin{path:PathBuf,sha256:Sha256Digest}
struct Original{file:fs::File,metadata:fs::Metadata,bytes:Vec<u8>,authority:operation::Authority}
impl Original{
    fn open(pin:&AuthorityPin)->Result<Self,String>{
        if !pin.path.is_absolute() || pin.path.components().any(|c|!matches!(c,Component::RootDir|Component::Normal(_))){
            return Err("native activation authority path is not canonical absolute".into());
        }
        for parent in pin.path.ancestors().skip(1){
            let metadata=fs::symlink_metadata(parent).map_err(|_|"activation authority parent")?;
            if !metadata.is_dir() || metadata.uid()!=0 || metadata.mode()&0o022!=0{
                return Err("activation authority parent is not protected".into());
            }
        }
        let named=fs::symlink_metadata(&pin.path).map_err(|_|"activation authority named original")?;
        validate_immutable_metadata(&named,true,"native activation authority")?;
        if named.gid()!=0 || named.nlink()!=1 || named.mode()&0o7777!=0o400
            || named.len()==0 || named.len()>8*1024*1024{return Err("native activation authority metadata or byte bound".into());}
        let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(&pin.path)
            .map_err(|_|"activation authority open")?;
        let metadata=file.metadata().map_err(|_|"activation authority metadata")?;
        if !Self::same(&named,&metadata){return Err("activation authority changed during open".into());}
        let mut bytes=vec![0;metadata.len() as usize];file.read_exact_at(&mut bytes,0).map_err(|_|"activation authority original read")?;
        if Sha256Digest::compute(&bytes)!=pin.sha256 || !Self::same(&metadata,&fs::symlink_metadata(&pin.path).map_err(|_|"activation authority named readback")?){
            return Err("activation authority original pin differs".into());
        }
        let authority=operation::Authority::admit(&bytes).map_err(shadow_error)?;
        let owner=Self{file,metadata,bytes,authority};owner.check()?;Ok(owner)
    }
    fn same(a:&fs::Metadata,b:&fs::Metadata)->bool{same_metadata(a,b)&&a.uid()==b.uid()&&a.gid()==b.gid()&&a.nlink()==b.nlink()}
    fn check(&self)->Result<(),String>{
        let current=self.file.metadata().map_err(|_|"activation retained authority metadata")?;
        if !Self::same(&current,&self.metadata){return Err("activation retained authority changed".into());}
        let mut bytes=vec![0;self.bytes.len()];self.file.read_exact_at(&mut bytes,0).map_err(|_|"activation retained authority read")?;
        if bytes!=self.bytes{return Err("activation retained authority bytes changed".into());}
        self.authority.require_original(&bytes).map_err(shadow_error)
    }
}
pub(crate) struct Prepared{original:Original,channel:transport::Prepared}
pub(crate) struct Owner{original:Original,channel:transport::Owner}
impl Prepared{
    pub(crate) fn open(config:Configuration,prepared:&native_serving_privileges::Prepared)->Result<Self,String>{
        prepared.check()?;
        let version=match config.api_version.as_str(){
            "serverware.nativePolicyActivationClient/v1"=>transport::ChannelVersion::UnixV1,
            "serverware.nativePolicyActivationClient/v2"=>transport::ChannelVersion::VsockV2,
            _=>return Err("native activation client not explicitly selected".into()),
        };
        if config.channel.version()?!=version{return Err("native activation client/channel profile mismatch".into());}
        let original=Original::open(&config.authority)?;
        let channel=transport::Prepared::take(config.channel,prepared)?;prepared.check()?;Ok(Self{original,channel})
    }
    pub(crate) fn bind(self,serving:Arc<native_serving_privileges::Owner>)->Result<Owner,String>{
        self.original.check()?;Ok(Owner{original:self.original,channel:self.channel.bind(serving)?})
    }
}
impl PolicyShadowGenerationControl{
    pub(crate) fn activate_native(&self,state:&GateState,raw:&[u8])->Result<Vec<u8>,GenerationInstallError>{
        let run=||->Result<Vec<u8>,String>{
            if !self.is_production || self.native_workers.is_none(){return Err("native activation requires real native generation owner".into());}
            let _installation=self.installation_lock.try_lock().map_err(|_|"native activation installation busy")?;
            let retained=self.retained_generation.try_lock().map_err(|_|"native activation generation busy")?
                .as_ref().cloned().ok_or("native activation has no actual retained generation")?;
            let mut selected=self.native_activation.try_lock().map_err(|_|"native activation client busy")?;
            let owner=selected.as_mut().ok_or("native activation client profile absent")?;
            owner.original.check()?;owner.channel.check()?;
            let verified=operation::VerifiedPrepared::verify(raw,&owner.original.authority,&retained.assignment,
                self.key_trust.as_ref(),retained.trusted_time.as_ref()).map_err(shadow_error)?;
            let p=verified.prepared();
            if operation::digest(p,"generationId").map_err(shadow_error)?!=*retained.generation_identity.generation_id()
                || operation::digest(p,"generationPublicationEnvelopeSha256").map_err(shadow_error)?!=retained.publication_receipt.internal_envelope_sha256
                || operation::integer(&p["publicationBefore"],"revision").map_err(shadow_error)? as u64
                    !=retained.publication_receipt.internal_envelope.untrusted_payload().custody.publication_revision{
                return Err("native activation substitutes actual retained generation publication".into());
            }
            super::super::native_canary_delivery::require_readiness(state,p)?;
            let before_time=super::super::native_canary_transport::boottime_ns()?;
            let(now_earliest,now_latest)=retained.trusted_time.now_interval_unix_nanos().map_err(shadow_error)?;
            let expires=operation::integer(p,"expiresAtUnixNanos").map_err(shadow_error)?;
            let now=super::super::native_canary_transport::boottime_ns()?;
            let remaining=u64::try_from(expires.checked_sub(now_latest).ok_or("native activation expiry")?).map_err(|_|"native activation expired")?;
            // Derive ONCE from the admitted original expiry, narrowing against
            // the same actual native lifetime. No receive/retry renews it.
            let deadline=owner.channel.deadline().min(before_time.checked_add(remaining).ok_or("native activation clock overflow")?);
            if before_time>now || now_earliest>now_latest || now>=deadline{return Err("native activation original allowance expired".into());}
            let original=&owner.original;
            let check=||{
                original.check()?;
                super::super::native_canary_delivery::require_readiness(state,verified.prepared())?;
                verified.check(&original.authority,self.key_trust.as_ref(),retained.trusted_time.as_ref()).map_err(shadow_error)
            };
            check()?;
            let result=owner.channel.publish(verified.request_original(),deadline,check)?;
            let receipt=operation::Publication::verify(&result,&verified,self.key_trust.as_ref(),retained.trusted_time.as_ref()).map_err(shadow_error)?;
            owner.original.check()?;owner.channel.check()?;
            verified.check(&owner.original.authority,self.key_trust.as_ref(),retained.trusted_time.as_ref()).map_err(shadow_error)?;
            // Public durable receipt only. CP finalization and immutable native
            // active-policy startup enrollment remain separately authorized.
            receipt.original().map_err(shadow_error)
        };
        run().map_err(GenerationInstallError::conflict)
    }
}
