//! Pre-drop role-key custody, separate from the serving gate/broker identity.
use super::{config::CustodyServiceRole as Role,guest_delivery::{PreparedRoleDelivery,ProvisioningSeed},
    guest_role_provisioning_files::Outputs,guest_role_provisioning_process::{Process,Slots}};
use crate::{native_serving_privileges::{Association,Owner as ServingOwner,Prepared},
    native_secret_broker_v1::ImageConfiguration,
    enclave_runtime_identity_v1::quote_guest_role_key_recipient,
    enclave_vsock_v1::VsockStreamV1,native_response_profile_v1::canonical_ascii_bytes};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD,Engine as _};
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use std::{collections::{BTreeMap,BTreeSet},io::{Read,Write},path::PathBuf};

const CHANNEL:&str="catchplate.nativeRoleKeyProvisionerChannel/v1";
const REQUEST:&str="catchplate.nativeRoleKeyKmsRecipientRequest/v1";
const RESPONSE:&str="catchplate.nativeRoleKeyKmsRecipientCiphertext/v1";
const MAX_KEYS:usize=64;
#[derive(Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Artifact {path:PathBuf,sha256:String}
#[derive(Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct GuestRoleKeyProvisionerConfiguration {
    api_version:String,helper_image:ImageConfiguration,kms_parent_port:u32,kms_key_id:String,
    ciphertext_blob_sha256:String,encryption_context:BTreeMap<String,String>,kek_sha256:String,
    encrypted_inventory:Artifact,
}
pub(super) fn ensure(value:bool,message:&str)->Result<(),String>{if value{Ok(())}else{Err(message.to_owned())}}
pub(super) fn now()->Result<u64,String>{crate::native_secret_broker_v1::now()}
pub(super) fn live(deadline:u64)->Result<(),String>{ensure(now()?<deadline,"role provisioning original interval expired")}
pub(super) fn sha(raw:&[u8])->String{format!("sha256:{}",hex::encode(Sha256::digest(raw)))}
fn hash(value:&str)->bool{value.len()==71 && value.starts_with("sha256:") && value[7..].bytes().all(|v|v.is_ascii_digit()||(b'a'..=b'f').contains(&v)) && value[7..] != "0".repeat(64)}
fn text(value:&str,maximum:usize)->bool{!value.is_empty()&&value.len()<=maximum&&!value.chars().any(char::is_control)}
fn fields(value:&Value,names:&[&str])->Result<(),String>{ensure(value.as_object().is_some_and(|v|v.len()==names.len()&&names.iter().all(|name|v.contains_key(*name))),"role provisioning closed fields differ")}
fn document(raw:&[u8],maximum:usize)->Result<Value,String>{
    ensure(!raw.is_empty()&&raw.len()<=maximum,"role provisioning original size differs")?;
    let value:Value=serde_json::from_slice(raw).map_err(|_|"role provisioning original JSON invalid")?;
    ensure(value.is_object()&&canonical_ascii_bytes(&value)?==raw,"role provisioning original is not exact canonical ASCII")?;Ok(value)
}
fn decoded(value:&Value,maximum:usize,exact:Option<usize>)->Result<Vec<u8>,String>{
    let value=value.as_str().ok_or("role provisioning encoding absent")?;
    ensure(!value.is_empty()&&value.len()<=(maximum*4+2)/3,"role provisioning encoding bound")?;
    let raw=URL_SAFE_NO_PAD.decode(value).map_err(|_|"role provisioning encoding invalid")?;
    ensure(!raw.is_empty()&&raw.len()<=maximum&&exact.is_none_or(|n|n==raw.len())&&URL_SAFE_NO_PAD.encode(&raw)==value,"role provisioning encoding differs")?;Ok(raw)
}
impl GuestRoleKeyProvisionerConfiguration {
    pub fn validate(&self)->Result<(),String>{
        ensure(self.api_version=="catchplate.nativeGuestRoleKeyProvisioner/v1" && self.kms_parent_port>1023 && self.kms_parent_port!=u32::MAX
            && text(&self.kms_key_id,2048) && self.helper_image.profile=="sealed-memfd-squashfs-v1"
            && self.helper_image.image_path=="/opt/catchplate/native-role-key-provisioner-runtime.squashfs"
            && self.encrypted_inventory.path==PathBuf::from("/run/catchplate-role-key-provisioning/inventory.enc.json"),"role provisioner fixed configuration differs")?;
        for pin in [&self.ciphertext_blob_sha256,&self.kek_sha256,&self.encrypted_inventory.sha256,
            &self.helper_image.image_sha256,&self.helper_image.interpreter_sha256,&self.helper_image.helper_sha256]{ensure(hash(pin),"role provisioner independent digest absent")?;}
        ensure((1..=32).contains(&self.encryption_context.len())&&canonical_ascii_bytes(&self.encryption_context)?.len()<=8192
            && self.encryption_context.get("catchplatePurpose").map(String::as_str)==Some("guest-role-keys/v1")
            && self.encryption_context.iter().all(|(key,value)|text(key,1024)&&text(value,1024)),"role provisioning KMS purpose/context differs")
    }
}

pub(crate) struct Owner {association:Association,outputs:Outputs,pid:libc::pid_t,boot:String}
impl Owner {
    pub(crate) fn provision(config:GuestRoleKeyProvisionerConfiguration,prepared:&Prepared,
        originals:&[&PreparedRoleDelivery])->Result<Self,String>{
        prepared.check()?;config.validate()?;
        ensure(originals.len()==Role::ALL.len(),"role provisioning requires every actual admitted delivery")?;
        let association=Association::capture(prepared)?;
        let mut keys:Vec<ProvisioningSeed>=Vec::new();let mut deliveries=Vec::new();
        let mut common=None;let mut deadline=prepared.deadline();let mut paths=BTreeSet::new();let mut uids=BTreeSet::new();
        for role in Role::ALL {
            let found:Vec<_>=originals.iter().filter(|owner|owner.scoped().role==role).collect();
            ensure(found.len()==1,"role provisioning delivery set repeats or omits a role")?;
            let original=*found[0];original.check().map_err(|e|e.to_string())?;
            let scoped=original.scoped();
            ensure(uids.insert(scoped.process.uid),"role provisioning cannot share signed service UIDs")?;
            let binding=(original.configuration_sha256().to_owned(),scoped.generation_id.clone(),scoped.generation,
                scoped.trust_checkpoint_sha256.clone(),original.boot_id().to_owned());
            ensure(common.as_ref().is_none_or(|old|old==&binding),"role provisioning configuration/generation/trust/boot differs")?;
            common=Some(binding);deadline=deadline.min(original.startup_deadline_boottime_ns().map_err(|e|e.to_string())?);
            deliveries.push(json!({"serviceRole":role,"deliverySha256":original.delivery_sha256()}));
            for key in original.provisioning_seeds().map_err(|e|e.to_string())? {
                ensure(paths.insert(key.path.clone())&&keys.len()<MAX_KEYS,"role provisioning seed paths repeat or exceed the bound")?;keys.push(key);
            }
        }
        let (configuration,generation_id,generation,trust,boot)=common.ok_or("role provisioning originals absent")?;
        ensure((7..=MAX_KEYS).contains(&keys.len()),"role provisioning complete seed count differs")?;live(deadline)?;
        let inventory=json!({"apiVersion":"catchplate.nativeGuestRoleKeyInventory/v1","configurationSha256":configuration,
            "generationId":generation_id,"generation":generation,"trustCheckpointSha256":trust,"bootId":boot,
            "deadlineBoottimeNs":deadline.to_string(),"deliveries":deliveries,"keys":keys});
        let inventory_raw=canonical_ascii_bytes(&inventory)?;
        ensure(inventory_raw.len()<=512*1024,"role provisioning public inventory bound")?;
        let inventory_sha=sha(&inventory_raw);
        let encrypted_raw=super::guest_role_provisioning_files::ciphertext(&config.encrypted_inventory.path,&config.encrypted_inventory.sha256,deadline)?;
        let encrypted=document(&encrypted_raw,32768)?;
        fields(&encrypted,&["apiVersion","inventorySha256","nonce","ciphertext"])?;
        ensure(encrypted["apiVersion"]=="catchplate.nativeGuestRoleKeyCiphertext/v1"&&encrypted["inventorySha256"]==inventory_sha,
            "role ciphertext is not assigned to these complete originals")?;
        decoded(&encrypted["nonce"],12,Some(12))?;ensure(decoded(&encrypted["ciphertext"],16384,None)?.len()>16,"role ciphertext lacks authentication tag")?;
        // Reserve exact FD numbers before opening outputs or spawning a child.
        let slots=Slots::reserve(keys.len())?;
        let mut outputs=Outputs::create(&keys,deadline)?;
        let descriptors=outputs.descriptors();
        let mut child=Process::spawn(&config.helper_image,outputs.take_writers()?,slots,deadline)?;
        let hello=document(&child.exchange(&canonical_ascii_bytes(&json!({"apiVersion":CHANNEL,"phase":"initialize",
            "deadlineBoottimeNs":deadline,"kekSha256":config.kek_sha256,"inventory":inventory,"outputs":descriptors}))?)?,4096)?;
        fields(&hello,&["apiVersion","phase","recipientPublicKey","recipientPublicKeySha256","nonce"])?;
        let public=decoded(&hello["recipientPublicKey"],1024,None)?;let nonce=decoded(&hello["nonce"],32,Some(32))?;
        ensure(hello["apiVersion"]==CHANNEL&&hello["phase"]=="recipient"&&hello["recipientPublicKeySha256"]==sha(&public),"actual role helper recipient differs")?;
        let request=json!({"apiVersion":REQUEST,"material":"guest-role-key-kek","configurationSha256":configuration,
            "deliveryInventorySha256":inventory_sha,"provisionerConfigurationSha256":sha(&canonical_ascii_bytes(&config)?),
            "helperImageSha256":config.helper_image.image_sha256,"bootId":boot,"deadlineBoottimeNs":deadline.to_string(),
            "kmsKeyId":config.kms_key_id,"ciphertextBlobSha256":config.ciphertext_blob_sha256,"encryptionContext":config.encryption_context,
            "recipientPublicKeySha256":sha(&public),"nonce":URL_SAFE_NO_PAD.encode(&nonce)});
        let request_raw=canonical_ascii_bytes(&request)?;let request_sha=sha(&request_raw);
        // A fresh fixed-ioctl owner at root, not a fabricated serving identity
        // or caller-supplied success. KMS remains the independent quote verifier.
        prepared.check()?;
        for original in originals {original.check().map_err(|e|e.to_string())?;}
        let quote=quote_guest_role_key_recipient(prepared,&public,&nonce,
            Sha256::digest(&request_raw).into(),deadline)?;
        let response=kms(&config,&request,&request_sha,&quote,deadline)?;
        let done=document(&child.exchange(&canonical_ascii_bytes(&json!({"apiVersion":CHANNEL,"phase":"provision",
            "request":request,"requestSha256":request_sha,"ciphertextForRecipient":response["ciphertextForRecipient"],
            "ciphertextSha256":response["ciphertextSha256"],"encryptedInventory":encrypted}))?)?,4096)?;
        fields(&done,&["apiVersion","phase","requestSha256","inventorySha256","files"])?;
        ensure(done["apiVersion"]==CHANNEL&&done["phase"]=="written"&&done["requestSha256"]==request_sha
            &&done["inventorySha256"]==inventory_sha&&done["files"].as_u64()==Some(keys.len() as u64),"role helper completion correlation differs")?;
        child.finish()?;outputs.finish(deadline)?;
        prepared.check()?;for original in originals{original.check().map_err(|e|e.to_string())?;}
        live(deadline)?;
        let result=Self{association,outputs,pid:unsafe{libc::getpid()},boot};result.check()?;Ok(result)
    }
    pub(crate) fn check(&self)->Result<(),String>{
        ensure(unsafe{libc::getpid()}==self.pid&&super::recovery::kernel_boot_id().map_err(|e|e.to_string())?==self.boot,
            "completed role output owner crossed process or boot")?;
        self.outputs.check()
    }
    pub(crate) fn require_serving(&self,owner:&ServingOwner)->Result<(),String>{self.association.require(owner)?;self.check()}
}
fn kms(config:&GuestRoleKeyProvisionerConfiguration,request:&Value,request_sha:&str,quote:&[u8],deadline:u64)->Result<Value,String>{
    let raw=canonical_ascii_bytes(&json!({"request":request,"requestSha256":request_sha,"attestationDocument":URL_SAFE_NO_PAD.encode(quote)}))?;
    ensure(raw.len()<=32768,"role KMS request bound")?;
    let mut transport=VsockStreamV1::connect_parent(config.kms_parent_port,deadline).map_err(|_|"fixed role KMS parent unavailable")?;
    transport.write_all(&(raw.len() as u32).to_be_bytes()).map_err(|_|"role KMS request outcome uncertain")?;
    transport.write_all(&raw).map_err(|_|"role KMS request outcome uncertain")?;
    let mut size=[0;4];transport.read_exact(&mut size).map_err(|_|"role KMS response unavailable; no retry")?;
    let size=u32::from_be_bytes(size) as usize;ensure(size>0&&size<=96*1024,"role KMS response bound")?;
    let mut raw=vec![0;size];transport.read_exact(&mut raw).map_err(|_|"role KMS response incomplete; no retry")?;
    transport.verify_connected_original(deadline).map_err(|_|"role KMS socket original changed")?;
    let value=document(&raw,96*1024)?;fields(&value,&["apiVersion","requestSha256","ciphertextForRecipient","ciphertextSha256"])?;
    let ciphertext=decoded(&value["ciphertextForRecipient"],65536,None)?;
    ensure(value["apiVersion"]==RESPONSE&&value["requestSha256"]==request_sha&&value["ciphertextSha256"]==sha(&ciphertext),"role KMS ciphertext original differs")?;
    live(deadline)?;Ok(value)
}
