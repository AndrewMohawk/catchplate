//! Independent CP trust and exact native READY/approval originals. This
//! purpose never accepts Fleet READY or a caller-selected verification key.
use super::*;
#[path="completion.rs"] mod completion;
const CONFIG:&str="catchplate.policyAuthorityServiceConfiguration/v6";
const SIGNED_CONFIG:&str="catchplate.signedPolicyAuthorityServiceConfiguration/v6";
pub(super) const OPERATION:&str="native-policy-activation.consume";
pub(super) const HANDLER:&str="catchplate_policy_authority_native_policy_activation_consume";
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct AuthorityConfiguration{
    api_version:String,root_public_key_base64url:String,root_spki_sha256:Sha256Digest,
    configuration_original_base64url:String,configuration_sha256:Sha256Digest,
}
pub(crate) struct Authority{original:Vec<u8>,configuration_original:Vec<u8>,payload:Value,digest:Sha256Digest,pid:u32}
pub(super) fn decode(text:&str,maximum:usize)->Result<Vec<u8>,ShadowError>{
    require(text.len()<=maximum.div_ceil(3)*4)?;let raw=URL_SAFE_NO_PAD.decode(text).map_err(fail)?;
    require(raw.len()<=maximum && URL_SAFE_NO_PAD.encode(&raw)==text)?;Ok(raw)
}
pub(super) fn framed(domain:&str,frames:&[&[u8]])->Sha256Digest{
    let mut h=Sha256::new();h.update(domain.as_bytes());h.update(b"\0");
    for frame in frames{h.update((frame.len() as u64).to_be_bytes());h.update(frame);}
    Sha256Digest(format!("sha256:{}",hex::encode(h.finalize())))
}
pub(super) fn key(text:&str)->Result<VerifyingKey,ShadowError>{
    let raw:[u8;32]=decode(text,32)?.try_into().map_err(fail)?;VerifyingKey::from_bytes(&raw).map_err(fail)
}
pub(super) fn public_spki(key:&VerifyingKey)->Sha256Digest{
    let mut bytes=vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00];bytes.extend_from_slice(key.as_bytes());Sha256Digest::compute(&bytes)
}
pub(super) fn verify_signature(public:&str,signature:&str,message:&[u8])->Result<(),ShadowError>{
    let bytes:[u8;64]=decode(signature,64)?.try_into().map_err(fail)?;
    key(public)?.verify_strict(message,&Signature::from_bytes(&bytes)).map_err(|_|ShadowError::SignatureInvalid)
}
pub(super) fn signed(value:&Value,public:&str,schema:&str)->Result<(),ShadowError>{
    require(value["schema"]==schema)?;let signature=text(value,"signature")?;
    let mut unsigned=value.clone();unsigned.as_object_mut().ok_or(ShadowError::BindingDrift)?.remove("signature");
    verify_signature(public,signature,framed(schema,&[&canonical_json_bytes(&unsigned)?]).as_str().as_bytes())
}
impl Authority{
    pub(crate) fn admit(raw:&[u8])->Result<Self,ShadowError>{
        let configuration:AuthorityConfiguration=serde_json::from_value(document(raw,8*1024*1024)?).map_err(fail)?;
        require(configuration.api_version=="catchplate.nativePolicyActivationAuthority/v1")?;
        let root=key(&configuration.root_public_key_base64url)?;
        require(public_spki(&root)==configuration.root_spki_sha256)?;
        let configuration_original=decode(&configuration.configuration_original_base64url,3*1024*1024)?;
        require(Sha256Digest::compute(&configuration_original)==configuration.configuration_sha256)?;
        let envelope=document(&configuration_original,3*1024*1024)?;
        exact(&envelope,&["schema","payload","signature"])?;
        let payload=envelope["payload"].clone();
        require(envelope["schema"]==SIGNED_CONFIG && payload["schema"]==CONFIG)?;
        verify_signature(&configuration.root_public_key_base64url,text(&envelope,"signature")?,
            framed(SIGNED_CONFIG,&[&canonical_json_bytes(&payload)?]).as_str().as_bytes())?;
        let digest=framed(CONFIG,&[&canonical_json_bytes(&payload)?]);
        let mut materials=BTreeSet::from([root.to_bytes()]);
        for role in ["verifier","planner"]{
            let item=&payload["roles"][role];
            require(materials.insert(key(text(item,"signingPublicKeyBase64Url")?)?.to_bytes()))?;
            if role=="planner"{require(item["enabledOperations"].as_array().ok_or(ShadowError::BindingDrift)?.iter().any(|value|value==OPERATION))?;}
            digest_field(item,"attestationReceiptDigest")?;
        }
        require(materials.insert(key(text(&payload["replayWitness"],"signingPublicKeyBase64Url")?)?.to_bytes()))?;
        digest_field(&payload,"sourceRevision")?;digest_field(&payload,"operationManifestDigest")?;digest_field(&payload,"queryManifestDigest")?;
        Ok(Self{original:raw.to_vec(),configuration_original,payload,digest,pid:std::process::id()})
    }
    pub(crate) fn require_original(&self,raw:&[u8])->Result<(),ShadowError>{require(self.pid==std::process::id() && self.original==raw)}
    pub(crate) fn check(&self,assignment:&VerifiedAssignment,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        require(self.pid==std::process::id())?;
        revalidate_verified_freshness(assignment,trust,time,MAX_ENVELOPE_AGE_NANOS)?;
        verify_assignment_authority_key_material(assignment,trust)?;
        let policy=&self.payload["policyCanaryNativeActivationPolicy"];
        exact(policy,&["schema","deploymentId","issuedAtEpochNs","expiresAtEpochNs","maximumActivationNanos","canaries","publicationKeys"])?;
        require(policy["schema"]=="catchplate.policyCanaryNativeActivationAuthorityPolicy/v1")?;
        validate_trusted_freshness(integer(policy,"issuedAtEpochNs")?,integer(policy,"expiresAtEpochNs")?,time,86_400_000_000_000)?;
        require((1_000_000_000..=300_000_000_000).contains(&integer(policy,"maximumActivationNanos")?))?;
        let canaries=policy["canaries"].as_array().ok_or(ShadowError::BindingDrift)?;
        require((1..=32).contains(&canaries.len()))?;let mut previous=None;let mut found=0;
        for canary in canaries{
            exact(canary,&["canaryId","assignmentSha256"])?;let name=text(canary,"canaryId")?;let sha=digest_field(canary,"assignmentSha256")?;
            require(!name.is_empty() && name.len()<=256 && previous.as_ref().is_none_or(|old|old<&(name.to_owned(),sha.clone())))?;
            previous=Some((name.to_owned(),sha.clone()));if &sha==assignment.envelope_sha256(){found+=1;}
        }require(found==1)?;
        let binding=assignment.payload().authority_key_independence.binding(AuthorityRole::CustodyActivationPublication,&assignment.payload().assignment_id)?;
        let checkpoint=trust.current_checkpoint()?;
        let local=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodyActivationPublication),&binding.key_id,&binding.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&local)==binding.key_material_sha256)?;
        let keys=policy["publicationKeys"].as_array().ok_or(ShadowError::BindingDrift)?;
        require((1..=32).contains(&keys.len()))?;let mut previous=None;let mut found=0;
        for item in keys{
            exact(item,&["keyId","publicKeyBase64Url"])?;
            let id=digest_field(item,"keyId")?;let public=key(text(item,"publicKeyBase64Url")?)?;
            require(public_spki(&public)==id && previous.as_ref().is_none_or(|old|old<&id))?;previous=Some(id.clone());
            if id==binding.key_id{require(public==local && id==binding.key_spki_sha256)?;found+=1;}
            for role in ["verifier","planner"]{require(public!=key(text(&self.payload["roles"][role],"signingPublicKeyBase64Url")?)?)?;}
        }require(found==1 && trust.current_checkpoint()?==checkpoint)
    }
}
fn digest_field(value:&Value,field:&str)->Result<Sha256Digest,ShadowError>{super::digest(value,field)}

pub(super) fn verify(request:&Request,authority:&Authority,assignment:&VerifiedAssignment,
    trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Value,ShadowError>{
    authority.check(assignment,trust,time)?;
    let prepared=completion::verify(request,authority,assignment,trust,time)?;
    exact(&prepared,&["apiVersion","activationId","replayId","canaryId","assignmentSha256","assignmentPayloadSha256","assignmentRevision",
        "authorityKeyIndependenceSha256","generationId","generationPublicationEnvelopeSha256","readyStateSha256","readinessRequestId",
        "readinessResultSha256","readinessCoreSha256","publicationBefore","publicationAfter","trustCheckpoint","approvalOriginal",
        "readinessOriginal","readyOriginal","controlPlaneConfigurationSha256","activationPolicySha256","issuedAtUnixNanos","expiresAtUnixNanos"])?;
    require(prepared["apiVersion"]=="catchplate.nativePolicyActivationPrepared/v1" && prepared["activationId"]==request.request_id
        && prepared["replayId"]==request.replay_id && digest_field(&prepared,"assignmentSha256")?==*assignment.envelope_sha256()
        && digest_field(&prepared,"assignmentPayloadSha256")?==*assignment.payload_sha256()
        && integer(&prepared,"assignmentRevision")? as u64==assignment.payload().assignment_revision
        && digest_field(&prepared,"authorityKeyIndependenceSha256")?==assignment.payload().authority_key_independence.independence_root_sha256
        && digest_field(&prepared,"controlPlaneConfigurationSha256")?==authority.digest
        && digest_field(&prepared,"activationPolicySha256")?==Sha256Digest::compute(&canonical_json_bytes(&authority.payload["policyCanaryNativeActivationPolicy"])?))?;
    publication_tuple(&prepared["publicationBefore"],true)?;publication_tuple(&prepared["publicationAfter"],false)?;
    let before=&prepared["publicationBefore"];let after=&prepared["publicationAfter"];
    require(integer(before,"revision")?<i64::MAX && integer(after,"policySequence")?>integer(before,"policySequence")?
        && rollback_epoch(after)?>=rollback_epoch(before)? && after["policySha256"]!=before["policySha256"])?;
    validate_trusted_freshness(integer(&prepared,"issuedAtUnixNanos")?,integer(&prepared,"expiresAtUnixNanos")?,time,300_000_000_000)?;
    let policy=&authority.payload["policyCanaryNativeActivationPolicy"];
    require(integer(&prepared,"expiresAtUnixNanos")?<=integer(policy,"expiresAtEpochNs")?
        && integer(&prepared,"expiresAtUnixNanos")?-integer(&prepared,"issuedAtUnixNanos")?<=integer(policy,"maximumActivationNanos")?
        && policy["canaries"].as_array().ok_or(ShadowError::BindingDrift)?.iter().any(|item|
            item["canaryId"]==prepared["canaryId"] && item["assignmentSha256"]==prepared["assignmentSha256"]))?;
    let readiness=document(text(&prepared,"readinessOriginal")?.as_bytes(),MAX_PREPARED)?;
    exact(&readiness,&["apiVersion","recordSha256","coverage","core","coreSha256","okForAction","activationApprovalConsumed","automaticRetryAllowed"])?;
    require(readiness["apiVersion"]=="catchplate.nativePolicyReadinessResult/v1"
        && readiness["coverage"]=="complete-native-fleet-readiness-derived" && readiness["okForAction"]==false
        && readiness["activationApprovalConsumed"]==false && readiness["automaticRetryAllowed"]==false
        && digest_field(&prepared,"readinessResultSha256")?==Sha256Digest::compute(&canonical_json_bytes(&readiness)?)
        && digest_field(&prepared,"readinessCoreSha256")?==Sha256Digest::compute(&canonical_json_bytes(&readiness["core"])?)
        && readiness["coreSha256"]==prepared["readinessCoreSha256"])?;
    let core=&readiness["core"];
    exact(core,&["apiVersion","canaryId","assignmentSha256","assignmentPayloadSha256","predecessorCanaryRevision","predecessorCanaryStateSha256",
        "designatedReadyRevision","policyIdentity","compilerAnalysisSha256","compilerAnalysisPayloadSha256","authorityAnalysis","pilotRestrictions",
        "fleet","memberEvidence","memberEvidenceRootSha256","aggregateCounters","readinessThresholds","calculatedRates",
        "responseValidationObligationsRootSha256","trustCheckpoint","currentPublication","readinessPolicySha256","issuedAtUnixNanos","expiresAtUnixNanos"])?;
    require(core["apiVersion"]=="catchplate.nativePolicyReadinessCore/v1" && core["canaryId"]==prepared["canaryId"]
        && core["assignmentSha256"]==prepared["assignmentSha256"] && core["assignmentPayloadSha256"]==prepared["assignmentPayloadSha256"]
        && canonical_json_bytes(&assignment.payload().fleet)?==canonical_json_bytes(&core["fleet"])?
        && canonical_json_bytes(&assignment.payload().policy_identity)?==canonical_json_bytes(&core["policyIdentity"])?
        && integer(&prepared,"expiresAtUnixNanos")?<=integer(core,"expiresAtUnixNanos")?)?;
    // CP and local custody have distinct checkpoint owners. Equality is only
    // demanded against the CP's authenticated current-root proof; no CP as-of
    // timestamp is relabelled as this guest's independently pinned key trust.
    let cp=&prepared["trustCheckpoint"];exact(cp,&["checkpointId","asOfUnixNanos","revocationGeneration","revocationRootSha256"])?;
    digest_field(cp,"checkpointId")?;digest_field(cp,"revocationRootSha256")?;integer(cp,"asOfUnixNanos")?;
    require(cp["revocationGeneration"].as_i64().is_some_and(|value|value>=0))?;
    authority.check(assignment,trust,time)?;require(canonical_json_bytes(&prepared)?.len()<=MAX_PREPARED)?;Ok(prepared)
}
