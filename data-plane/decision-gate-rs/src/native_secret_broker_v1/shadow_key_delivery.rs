//! Ciphertext-only mechanism. The binary's genuine C9/assignment/closure owner
//! admits it; these data types are not a custody permission or key constructor.
use super::{canonical_ascii_bytes,decoded,digest,document,encoded,ensure,fields,live,sha,ImageConfiguration};
use crate::{enclave_runtime_identity_v1::{CredentialRecipientV1,ShadowRecipientQuoteV1},
    enclave_vsock_v1::VsockStreamV1};
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use std::{collections::BTreeMap,io::{Read,Write}};
#[path="shadow_key_process.rs"] mod process;
pub const IMAGE_PATH:&str="/opt/serverware/native-shadow-key-delivery-runtime.squashfs";
pub(super) const HELPER_PATH:&str="/opt/serverware/serverware/native_shadow_key_helper.py";
const CHANNEL:&str="serverware.nativeShadowKeyDeliveryChannel/v1";
pub const OUTPUT_DOMAIN:&[u8]=b"serverware/native-shadow-role-recipient-ciphertext/v1\0";
pub(crate) const QUOTE_DOMAIN:&[u8]=b"serverware/native-shadow-kms-recipient/v1\0";
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Configuration {
    pub api_version:String,pub kms_parent_port:u32,pub kms_key_id:String,pub ciphertext_blob_sha256:String,
    pub encryption_context:BTreeMap<String,String>,pub kek_sha256:String,pub helper_image:ImageConfiguration,
    pub encrypted_inventory_sha256:String,
}
impl Configuration {
    pub fn validate(&self)->Result<(),String> {
        ensure(self.api_version=="serverware.nativeShadowKeyKmsTransport/v1" && self.kms_parent_port>1023
            && self.kms_parent_port!=u32::MAX && !self.kms_key_id.is_empty() && self.kms_key_id.len()<=2048
            && !self.kms_key_id.chars().any(char::is_control),"shadow KMS fixed transport differs")?;
        for pin in [&self.ciphertext_blob_sha256,&self.kek_sha256,&self.encrypted_inventory_sha256,
            &self.helper_image.image_sha256,&self.helper_image.interpreter_sha256,&self.helper_image.helper_sha256] {digest(pin)?;}
        ensure(self.helper_image.profile=="sealed-memfd-squashfs-v1"&&self.helper_image.image_path==IMAGE_PATH,
            "shadow KMS helper purpose differs")?;
        ensure((1..=32).contains(&self.encryption_context.len())&&canonical_ascii_bytes(&self.encryption_context)?.len()<=8192
            && self.encryption_context.get("serverwarePurpose").map(String::as_str)==Some("native-shadow-local-role-keys/v1")
            && self.encryption_context.iter().all(|(k,v)|!k.is_empty()&&k.len()<=1024&&!v.is_empty()&&v.len()<=1024
                && !k.chars().chain(v.chars()).any(char::is_control)),"shadow KMS admitted encryption context differs")
    }
}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
pub struct Binding {
    pub api_version:String,pub guest:Value,pub key_authorization_sha256:String,pub delivery_authorization_sha256:String,
    pub inventory:Value,pub challenge_base64url:String,pub execution_closure_manifest_sha256:String,
    pub worker_executable_sha256:String,pub structurally_verified_seccomp_policy_sha256:String,
}
impl Binding {
    fn validate(&self,uid:u32,gid:u32,deadline:u64)->Result<[u8;32],String> {
        ensure(self.api_version=="serverware.nativeShadowKeyDeliveryBinding/v1","shadow delivery binding purpose differs")?;
        for p in [&self.key_authorization_sha256,&self.delivery_authorization_sha256,&self.execution_closure_manifest_sha256,
            &self.worker_executable_sha256,&self.structurally_verified_seccomp_policy_sha256]{digest(p)?;}
        fields(&self.guest,&["configurationSha256","deliverySha256","runtimeConfigurationSha256","serviceRole","uid","gid",
            "bootIdBase64url","timeNamespaceDevice","timeNamespaceInode","issuedAtBoottimeNs","startupDeadlineBoottimeNs",
            "lifetimeDeadlineBoottimeNs","invocationId"])?;
        ensure(self.guest["uid"].as_u64()==Some(uid.into())&&self.guest["gid"].as_u64()==Some(gid.into())
            && self.guest["startupDeadlineBoottimeNs"]==deadline.to_string(),"shadow role/deadline original differs")?;
        fields(&self.inventory,&["apiVersion","fullKeySetRootSha256","localKeySetRootSha256","localKeys"])?;
        ensure(self.inventory["apiVersion"]=="serverware.nativeShadowLocalKeyInventory/v1"
            && self.inventory["localKeys"].as_array().is_some_and(|v|(1..=16).contains(&v.len())),"shadow local inventory differs")?;
        for name in ["fullKeySetRootSha256","localKeySetRootSha256"] {digest(self.inventory[name].as_str().ok_or("shadow key root absent")?)?;}
        let challenge=decoded(&Value::String(self.challenge_base64url.clone()),32,Some(32))?;
        ensure(challenge.iter().any(|b|*b!=0),"shadow original nonce absent")?;
        let mut preimage=b"serverware/native-shadow-kms-nonce/v1\0".to_vec();preimage.extend_from_slice(&challenge);
        Ok(Sha256::digest(&preimage).into())
    }
}
pub struct PreparedShadowKeyHelper {process:process::Process,configuration:Configuration,uid:u32,gid:u32,deadline:u64}
impl PreparedShadowKeyHelper {
    pub fn open(configuration:Configuration,uid:u32,gid:u32,deadline:u64)->Result<Self,String> {
        configuration.validate()?;let process=process::Process::open(&configuration.helper_image,uid,gid,deadline)?;
        Ok(Self{process,configuration,uid,gid,deadline})
    }
    /// Only actual process-held X25519 owner is accepted; no public-key DTO.
    pub fn begin(mut self,binding:Binding,recipient:&CredentialRecipientV1,ciphertext_original:Vec<u8>)->Result<ShadowKeyRecipient,String> {
        self.process.final_identity()?;self.process.check()?;
        let nonce=binding.validate(self.uid,self.gid,self.deadline)?;
        ensure(sha(&ciphertext_original)==self.configuration.encrypted_inventory_sha256,"shadow ciphertext original changed")?;
        let encrypted=document(&ciphertext_original,32768)?;
        fields(&encrypted,&["apiVersion","inventorySha256","nonce","ciphertext"])?;
        ensure(encrypted["apiVersion"]=="serverware.nativeShadowEncryptedLocalKeys/v1"
            && encrypted["inventorySha256"]==sha(&canonical_ascii_bytes(&binding.inventory)?),"shadow ciphertext inventory differs")?;
        decoded(&encrypted["nonce"],12,Some(12))?;
        ensure(decoded(&encrypted["ciphertext"],16384,None)?.len()>16,"shadow ciphertext authentication absent")?;
        let role_public=recipient.public_key_bytes()?;
        let start=canonical_ascii_bytes(&json!({"apiVersion":CHANNEL,"phase":"initialize","binding":binding,
            "transport":self.configuration,"roleRecipientPublicKey":encoded(&role_public)}))?;
        let hello=document(&self.process.exchange(&start)?,4096)?;
        fields(&hello,&["apiVersion","phase","recipientPublicKey","recipientPublicKeySha256"])?;
        let rsa=decoded(&hello["recipientPublicKey"],1024,None)?;
        ensure(hello["apiVersion"]==CHANNEL&&hello["phase"]=="recipient"&&hello["recipientPublicKeySha256"]==sha(&rsa),
            "shadow real helper RSA original differs")?;
        let request=json!({"apiVersion":"serverware.nativeShadowKeyKmsRecipientRequest/v1","material":"shadow-local-key-kek",
            "binding":binding,"transport":self.configuration,"recipientPublicKeySha256":sha(&rsa),
            "roleRecipientPublicKey":encoded(&role_public),"nonce":encoded(&nonce),"deadlineBoottimeNs":self.deadline.to_string()});
        let request_sha=sha(&canonical_ascii_bytes(&request)?);
        self.process.check()?;
        Ok(ShadowKeyRecipient{process:self.process,configuration:self.configuration,request,request_sha,
            rsa,nonce,encrypted,deadline:self.deadline,quoted:false})
    }
}
/// RSA provenance comes solely from the owned fixed child channel. No public
/// constructor, supplied-key import, reset, cloning or secret-output method.
pub struct ShadowKeyRecipient {process:process::Process,configuration:Configuration,request:Value,request_sha:String,
    rsa:Vec<u8>,nonce:[u8;32],encrypted:Value,deadline:u64,quoted:bool}
impl ShadowKeyRecipient {
    pub(crate) fn quote_inputs(&mut self,deadline:u64)->Result<(Vec<u8>,[u8;32],[u8;32]),String> {
        self.process.final_identity()?;self.process.check()?;
        ensure(!self.quoted&&deadline==self.deadline,"shadow recipient quote cannot replay/renew")?;self.quoted=true;
        Ok((self.rsa.clone(),self.nonce,digest(&self.request_sha)?))
    }
    pub fn request_sha256(&self)->&str {&self.request_sha}
    pub fn nonce(&self)->[u8;32] {self.nonce}
    pub fn provision(mut self,quote:ShadowRecipientQuoteV1)->Result<Value,String> {
        self.process.final_identity()?;self.process.check()?;
        ensure(self.quoted&&quote.public_key()==self.rsa&&quote.nonce()==&self.nonce
            && quote.request_sha256()==&digest(&self.request_sha)?,"shadow recipient original quote differs")?;
        let raw=canonical_ascii_bytes(&json!({"request":self.request,"requestSha256":self.request_sha,
            "attestationDocument":encoded(quote.document())}))?;
        ensure(raw.len()<=32768,"shadow KMS request bound")?;
        let mut socket=VsockStreamV1::connect_parent(self.configuration.kms_parent_port,self.deadline)
            .map_err(|_|"shadow fixed KMS parent unavailable")?;
        socket.write_all(&(raw.len() as u32).to_be_bytes()).and_then(|_|socket.write_all(&raw))
            .map_err(|_|"shadow KMS contact uncertain; no retry")?;
        let mut size=[0;4];socket.read_exact(&mut size).map_err(|_|"shadow KMS response unavailable")?;
        let size=u32::from_be_bytes(size) as usize;ensure(size>0&&size<=96*1024,"shadow KMS response bound")?;
        let mut raw=vec![0;size];socket.read_exact(&mut raw).map_err(|_|"shadow KMS response incomplete")?;
        socket.verify_connected_original(self.deadline).map_err(|_|"shadow KMS original transport changed")?;
        let response=document(&raw,96*1024)?;
        fields(&response,&["apiVersion","requestSha256","ciphertextForRecipient","ciphertextSha256"])?;
        let cms=decoded(&response["ciphertextForRecipient"],65536,None)?;
        ensure(response["apiVersion"]=="serverware.nativeShadowKeyKmsRecipientCiphertext/v1"
            && response["requestSha256"]==self.request_sha&&response["ciphertextSha256"]==sha(&cms),"shadow KMS CMS original differs")?;
        self.process.check()?;
        let frame=canonical_ascii_bytes(&json!({"apiVersion":CHANNEL,"phase":"provision","request":self.request,
            "requestSha256":self.request_sha,"ciphertextForRecipient":encoded(&cms),"ciphertextSha256":sha(&cms),
            "encryptedInventory":self.encrypted}))?;
        let output=document(&self.process.exchange(&frame)?,32768)?;
        fields(&output,&["apiVersion","requestSha256","recipientPublicKey","serverEphemeralPublicKey","aeadNonce","ciphertext"])?;
        ensure(output["apiVersion"]=="serverware.nativeShadowRoleRecipientCiphertext/v1"
            && output["requestSha256"]==self.request_sha&&output["recipientPublicKey"]==self.request["roleRecipientPublicKey"],
            "shadow role output original differs")?;
        decoded(&output["serverEphemeralPublicKey"],32,Some(32))?;decoded(&output["aeadNonce"],12,Some(12))?;
        decoded(&output["ciphertext"],16384,None)?;
        self.process.finish()?;live(self.deadline)?;Ok(output)
    }
}
