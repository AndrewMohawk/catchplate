//! Separately assigned native ledger heartbeat. This is not a Fleet envelope.
use crate::native_response_profile_v1::canonical_ascii_bytes as ascii;
use crate::native_canary_evidence_v1::{now_epoch,now_boot};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD,Engine as _};
use serde_json::Value;
use sha2::{Digest,Sha256};
pub const SCHEMA:&str="catchplate.nativePolicyShadowHeartbeatStatement/v1";
pub const RECORD:&str="catchplate.nativePolicyShadowHeartbeat/v1";
pub const POLICY:&str="catchplate.policyCanaryHeartbeatAuthorityPolicy/v1";
pub const PURPOSE:&str="native-policy-shadow-heartbeat";
pub const QUOTE_DOMAIN:&[u8]=b"catchplate/native-policy-shadow-heartbeat-attestation/v1\0";
pub const MAX_RECORD:usize=64*1024;
pub const MAX_HEARTBEATS:usize=32;
pub const FIELDS:&[&str]=&["apiVersion","purpose","deploymentId","instanceId","holderId","bootId","keyId",
    "controlPlaneResponseSigningKeyId","policyHash","dataPlaneBinarySha256","purposeAssignmentSha256","canaryId",
    "canaryAssignmentSha256","canaryBootId","assignmentPayloadSha256","loadReceiptSha256","publicationSha256",
    "generationId","runtimeIdentitySha256","heartbeatSequence","previousHeartbeatSha256","baselineEventOrdinal",
    "baselineHeadSha256","eventOrdinal","headSha256","originalCount","lastIngressSequence","openingReceiptSha256",
    "observedAtUnixNanos","issuedAtEpochNs","expiresAtEpochNs","nonce"];
fn require(value:bool,message:&str)->Result<(),String>{if value{Ok(())}else{Err(message.into())}}
fn exact(value:&Value,fields:&[&str])->Result<(),String>{let object=value.as_object().ok_or("heartbeat object")?;
    require(object.len()==fields.len() && fields.iter().all(|field|object.contains_key(*field)),"heartbeat closed fields")}
pub fn text<'a>(value:&'a Value,name:&str)->Result<&'a str,String>{value[name].as_str().ok_or_else(||format!("heartbeat {name}"))}
pub fn number(value:&Value,name:&str)->Result<u64,String>{value[name].as_u64().filter(|v|*v<=i64::MAX as u64).ok_or_else(||format!("heartbeat {name}"))}
pub fn validate_policy(value:&Value,deployment:&str,now:u64)->Result<(),String>{
    exact(value,&["schema","deploymentId","issuedAtEpochNs","expiresAtEpochNs","operationMaxSeconds","maximumGapNanos","trustRoots","assignments"])?;
    let issued=number(value,"issuedAtEpochNs")?;let expires=number(value,"expiresAtEpochNs")?;
    require(value["schema"]==POLICY && value["deploymentId"]==deployment && issued<=now && now<expires
        && expires.checked_sub(issued).is_some_and(|v|v<=86_400_000_000_000)
        && (1..=30).contains(&number(value,"operationMaxSeconds")?)
        && (1_000_000_000..=60_000_000_000).contains(&number(value,"maximumGapNanos")?)
        && value["trustRoots"]["apiVersion"]=="catchplate.policyCanaryHeartbeatTrustRoots/v1"
        && value["assignments"].as_array().is_some_and(|v|(1..=32).contains(&v.len())),"heartbeat independent current policy")?;
    exact(&value["trustRoots"],&["apiVersion","awsNitroRootCertificatesPem","awsNitroCrlsDerBase64url","nitroCertificateProfile"])?;
    require(ascii(value)?.len()<=2*1024*1024,"heartbeat policy original bound")?;
    let mut previous=None;
    for item in value["assignments"].as_array().ok_or("heartbeat assignment array")? {
        exact(item,&["holderId","bootId","keyId","controlPlaneResponseSigningKeyId","releaseRecordSha256","policyHash",
            "configurationSha256","caCertificateSha256","caPublicKeySpkiSha256","expectedBinaryDigest","expectedPcrs",
            "expectedEif","expectedModuleId","maxAgeSeconds","futureSkewSeconds","instanceId","canaryId","canaryAssignmentSha256","canaryBootId"])?;
        for name in ["holderId","keyId","controlPlaneResponseSigningKeyId","releaseRecordSha256","policyHash","configurationSha256",
            "caCertificateSha256","caPublicKeySpkiSha256","expectedBinaryDigest","canaryAssignmentSha256","canaryBootId"] {
            require(crate::native_currentness_v1::digest(text(item,name)?),"heartbeat assignment digest")?;
        }
        require(text(item,"holderId")?==crate::native_currentness_v1::holder_id(text(item,"bootId")?,text(item,"keyId")?)?
            && item["keyId"]!=item["controlPlaneResponseSigningKeyId"]
            && crate::native_canary_evidence_v1::component(text(item,"instanceId")?)
            && !text(item,"canaryId")?.is_empty() && text(item,"canaryId")?.chars().count()<=256
            && (1..=300).contains(&number(item,"maxAgeSeconds")?) && number(item,"futureSkewSeconds")?<=30,
            "heartbeat assignment scope")?;
        let identity=(text(item,"canaryId")?.to_owned(),text(item,"instanceId")?.to_owned(),text(item,"holderId")?.to_owned());
        require(previous.as_ref().map_or(true,|old|old<&identity),"heartbeat assignments not sorted unique")?;
        previous=Some(identity);
    }Ok(())
}
pub fn validate(statement:&Value,now:u64)->Result<(),String>{
    exact(statement,FIELDS)?;
    require(statement["apiVersion"]==SCHEMA && statement["purpose"]==PURPOSE,"heartbeat explicit purpose")?;
    for name in ["holderId","keyId","controlPlaneResponseSigningKeyId","policyHash","dataPlaneBinarySha256",
        "purposeAssignmentSha256","canaryAssignmentSha256","canaryBootId","assignmentPayloadSha256","loadReceiptSha256",
        "publicationSha256","generationId","runtimeIdentitySha256","previousHeartbeatSha256","baselineHeadSha256","headSha256"]{
        require(crate::native_currentness_v1::digest(text(statement,name)?),"heartbeat digest")?;
    }
    for name in ["deploymentId","instanceId"]{require(crate::native_canary_evidence_v1::component(text(statement,name)?),"heartbeat component")?;}
    let canary=text(statement,"canaryId")?;require(!canary.is_empty() && canary.chars().count()<=256,"heartbeat canary")?;
    crate::native_currentness_v1::bytes32(text(statement,"nonce")?)?;
    require(text(statement,"holderId")?==crate::native_currentness_v1::holder_id(text(statement,"bootId")?,text(statement,"keyId")?)?,"heartbeat holder")?;
    let issued=number(statement,"issuedAtEpochNs")?;let expires=number(statement,"expiresAtEpochNs")?;
    require(issued>0 && issued<=now && now<expires && expires-issued<=30_000_000_000
        && number(statement,"observedAtUnixNanos")?==issued && (1..=32).contains(&number(statement,"heartbeatSequence")?)
        && number(statement,"eventOrdinal")?.checked_sub(number(statement,"baselineEventOrdinal")?)==Some(number(statement,"originalCount")?)
        && number(statement,"originalCount")?<=64,"heartbeat original time/complete head")?;
    match (&statement["lastIngressSequence"],&statement["openingReceiptSha256"]){
        (Value::Null,Value::Null)=>{},(sequence,Value::String(digest))=>require(sequence.as_u64().is_some_and(|v|v>0 && v<=i64::MAX as u64)
            && crate::native_currentness_v1::digest(digest),"heartbeat actual opening")?,
        _=>return Err("heartbeat required-null opening pair".into()),
    }Ok(())
}
/// Private retained preparation; no signer accepts caller success booleans.
pub struct Prepared {statement:Value,deadline:u64,pid:u32}
impl Prepared {
    pub fn new(statement:Value,deadline:u64)->Result<Self,String>{let result=Self{statement,deadline,pid:std::process::id()};result.check(deadline)?;Ok(result)}
    pub fn statement(&self)->&Value{&self.statement}
    pub fn deadline(&self)->u64{self.deadline}
    pub fn check(&self,deadline:u64)->Result<(),String>{
        let now=now_epoch()?;validate(&self.statement,now)?;
        let remaining=deadline.min(self.deadline).checked_sub(now_boot()?).ok_or("heartbeat original deadline elapsed")?;
        require(self.pid==std::process::id() && remaining>0
            && number(&self.statement,"expiresAtEpochNs")?<=now.checked_add(remaining).ok_or("heartbeat epoch overflow")?,
            "heartbeat original owner deadline")
    }
    pub fn preimage(&self)->Result<Vec<u8>,String>{let mut value=SCHEMA.as_bytes().to_vec();value.push(0);value.extend(ascii(&self.statement)?);Ok(value)}
    pub(crate) fn attestation_nonce(&self,signature:&[u8;64])->Result<[u8;32],String>{
        let mut hash=Sha256::new();hash.update(QUOTE_DOMAIN);hash.update(crate::native_currentness_v1::bytes32(text(&self.statement,"nonce")?)?);
        hash.update(Sha256::digest(ascii(&self.statement)?));hash.update(signature);Ok(hash.finalize().into())
    }
    pub(crate) fn signed(&self,signature:&[u8;64],key:&[u8],quote:&[u8])->Result<Value,String>{
        self.check(self.deadline)?;
        let value=serde_json::json!({"statement":self.statement,"signature":format!("ed25519:{}",URL_SAFE_NO_PAD.encode(signature)),
            "nativeKeyEvidence":{"apiVersion":"catchplate.nativeResponseProofKeyEvidence/v1","responseProofPublicKey":URL_SAFE_NO_PAD.encode(key),
                "attestationDocumentB64":URL_SAFE_NO_PAD.encode(quote)}});
        require(ascii(&value)?.len()<=MAX_RECORD,"heartbeat evidence bound")?;Ok(value)
    }
}
