use super::wire::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CONFIG_SCHEMA: &str = "serverware.policyAuthorityServiceConfiguration/v6";
pub const SIGNED_CONFIG_SCHEMA: &str = "serverware.signedPolicyAuthorityServiceConfiguration/v6";
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct CanaryBinding {
    pub canary_id:String, pub canary_assignment_sha256:String, pub canary_boot_id:String,
    pub intake_purpose_assignment_sha256:String, pub delivery_purpose_assignment_sha256:String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct RecoveryTarget {pub canary_id:String,pub slot_id:String,pub http_sha256:String,pub part_count:u64,pub original_expires_at_epoch_ns:u64}
impl RecoveryTarget{
    pub fn selector(&self)->super::Selector{super::Selector{slot_id:self.slot_id.clone(),http_sha256:self.http_sha256.clone(),part_count:self.part_count}}
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub api_version:String, pub intake_url:String, pub deployment_id:String, pub instance_id:String,
    pub authority_root_public_key_base64_url:String, pub authority_root_spki_sha256:String,
    pub authority_configuration_original_base64_url:String, pub authority_configuration_sha256:String,
    pub canaries:Vec<CanaryBinding>,
    pub recovery_targets:Vec<RecoveryTarget>,
}
impl Configuration {
    pub fn validate(&self)->Result<(),String> { Authority::admit(self.clone()).map(|_|()) }
}
/// Created only from the explicit native cold configuration. No HTTP field can
/// replace its root, complete configuration original, assignments or source.
pub struct Authority { pub(crate) config:Configuration, pub(crate) payload:Value,
    pub(crate) original:Vec<u8>, pub(crate) digest:String, pid:u32 }
pub(crate) fn verify(key:&str, signature:&str, message:&[u8])->Result<(),String> {
    let key:[u8;32]=decode(key,32)?.try_into().map_err(|_|"canary authority key length")?;
    let signature:[u8;64]=decode(signature,64)?.try_into().map_err(|_|"canary authority signature length")?;
    VerifyingKey::from_bytes(&key).map_err(|_|"canary authority key")?.verify(message,&Signature::from_bytes(&signature))
        .map_err(|_|"canary authority original signature".into())
}
pub(crate) fn signed(value:&Value,key:&str,schema:&str)->Result<(),String> {
    require(value["schema"]==schema,"canary signed profile")?;
    let mut unsigned=value.clone(); unsigned.as_object_mut().ok_or("canary signed object")?.remove("signature");
    verify(key,text(value,"signature")?,framed(schema,&[&ascii(&unsigned)?]).as_bytes())
}
impl Authority {
    pub fn admit(config:Configuration)->Result<Self,String> {
        require(matches!(config.api_version.as_str(),"serverware.nativeCanaryDurableDelivery/v1"|"serverware.nativeCanaryDurableDelivery/v2"|"serverware.nativeCanaryDurableDelivery/v3")
            && crate::native_canary_evidence_v1::component(&config.deployment_id)
            && crate::native_canary_evidence_v1::component(&config.instance_id)
            && (1..=16).contains(&config.canaries.len()),"native canary cold profile")?;
        let url=url::Url::parse(&config.intake_url).map_err(|_|"canary cold intake URL")?;
        require(url.scheme()=="https" && url.host_str().is_some() && url.path()==crate::native_canary_evidence_v1::INTAKE_PATH
            && url.username().is_empty() && url.password().is_none() && url.query().is_none() && url.fragment().is_none(),"canary fixed cold URL")?;
        let key=decode(&config.authority_root_public_key_base64_url,32)?; require(key.len()==32,"canary cold root length")?;
        let mut spki=hex::decode("302a300506032b6570032100").map_err(|_|"canary source SPKI prefix")?; spki.extend(&key);
        require(crate::sha256_prefixed(&spki)==config.authority_root_spki_sha256,"canary independently pinned root SPKI")?;
        let original=decode(&config.authority_configuration_original_base64_url,3*1024*1024)?;
        require(crate::sha256_prefixed(&original)==config.authority_configuration_sha256,"canary cold configuration original pin")?;
        // Authority files need not be canonical on disk; their signed full
        // payload is always canonical. Exact original bytes remain retained.
        let envelope=crate::parse_json_without_duplicate_keys(&original).map_err(|e|e.to_string())?;
        exact(&envelope,&["schema","payload","signature"])?;
        require(envelope["schema"]==SIGNED_CONFIG_SCHEMA && envelope["payload"]["schema"]==CONFIG_SCHEMA,"canary authority configuration profile")?;
        let payload=envelope["payload"].clone();
        verify(&config.authority_root_public_key_base64_url,text(&envelope,"signature")?,framed(SIGNED_CONFIG_SCHEMA,&[&ascii(&payload)?]).as_bytes())?;
        let digest=framed(CONFIG_SCHEMA,&[&ascii(&payload)?]);
        let mut seen=std::collections::BTreeSet::new();
        for binding in &config.canaries {
            require(!binding.canary_id.is_empty() && binding.canary_id.chars().count()<=256 && seen.insert(binding.canary_id.clone())
                && [&binding.canary_assignment_sha256,&binding.canary_boot_id,&binding.intake_purpose_assignment_sha256,&binding.delivery_purpose_assignment_sha256]
                    .iter().all(|s|crate::native_currentness_v1::digest(s)),"canary cold assignment inventory")?;
            let intake=assignment(&payload["policyCanaryIntakePolicy"],&binding.intake_purpose_assignment_sha256)?;
            let delivery=assignment(&payload["policyCanaryDeliveryPolicy"],&binding.delivery_purpose_assignment_sha256)?;
            for selected in [intake,delivery] {
                require(selected["canaryId"]==binding.canary_id && selected["instanceId"]==config.instance_id
                    && selected["canaryAssignmentSha256"]==binding.canary_assignment_sha256 && selected["canaryBootId"]==binding.canary_boot_id,
                    "canary cold assignment differs from independently signed policy")?;
            }
            require(delivery["intakePurposeAssignmentSha256"]==binding.intake_purpose_assignment_sha256,"delivery assignment does not name intake purpose")?;
        }
        require(config.recovery_targets.len()<=16,"canary recovery selector capacity")?;
        let mut targets=std::collections::BTreeSet::new();
        for target in &config.recovery_targets{
            target.selector().validate()?;
            require(seen.contains(&target.canary_id) && targets.insert(target.slot_id.clone())
                && target.original_expires_at_epoch_ns>0 && target.original_expires_at_epoch_ns<=i64::MAX as u64,"canary explicit recovery selector")?;
        }
        let result=Self{config,payload,original,digest,pid:std::process::id()}; result.check()?;
        if result.native_finalization_selected()? {
            for binding in &result.config.canaries {result.finalization_assignment(&binding.canary_id)?;}
        } else if result.native_cumulative_selected()? {
            for binding in &result.config.canaries {result.heartbeat_assignment(&binding.canary_id)?;}
        }
        Ok(result)
    }
    pub fn configuration(&self)->&Configuration { &self.config }
    pub fn native_readiness_policy(&self)->Result<&Value,String> {
        self.check()?;
        require(self.config.api_version=="serverware.nativeCanaryDurableDelivery/v3","native readiness requires explicit finalization profile")?;
        let policy=&self.payload["policyCanaryNativeReadinessPolicy"];
        exact(policy,&["schema","deploymentId","issuedAtEpochNs","expiresAtEpochNs","maximumReadinessAgeNanos","canaries"])?;
        let now=crate::native_canary_evidence_v1::now_epoch()?;
        let issued=number(policy,"issuedAtEpochNs")?;let expires=number(policy,"expiresAtEpochNs")?;
        require(policy["schema"]=="serverware.policyCanaryNativeReadinessAuthorityPolicy/v1"
            && policy["deploymentId"]==self.config.deployment_id && issued<=now && now<expires
            && expires.checked_sub(issued).is_some_and(|value|value<=86_400_000_000_000)
            && (1_000_000_000..=300_000_000_000).contains(&number(policy,"maximumReadinessAgeNanos")?),
            "native readiness independent policy scope/lifetime")?;
        let canaries=policy["canaries"].as_array().ok_or("native readiness policy canaries")?;
        require((1..=32).contains(&canaries.len()) && ascii(policy)?.len()<=8192,"native readiness policy capacity")?;
        let mut previous=None;
        for item in canaries {
            exact(item,&["canaryId","assignmentSha256"])?;
            let id=text(item,"canaryId")?;let assignment=text(item,"assignmentSha256")?;
            require(!id.is_empty() && id.chars().count()<=256 && crate::native_currentness_v1::digest(assignment),
                "native readiness policy canary identity")?;
            let pair=(id,assignment);require(previous.is_none_or(|old|old<pair),"native readiness policy order/duplicate")?;
            previous=Some(pair);
        }
        Ok(policy)
    }
    pub fn native_cumulative_selected(&self)->Result<bool,String> {
        if self.config.api_version=="serverware.nativeCanaryDurableDelivery/v1" {return Ok(false);}
        self.check()?;
        Ok(matches!(self.config.api_version.as_str(),"serverware.nativeCanaryDurableDelivery/v2"|"serverware.nativeCanaryDurableDelivery/v3"))
    }
    pub fn native_finalization_selected(&self)->Result<bool,String> {
        if self.config.api_version!="serverware.nativeCanaryDurableDelivery/v3" {return Ok(false);}
        self.check()?;Ok(true)
    }
    pub fn finalization_policy(&self)->Result<&Value,String> {
        require(self.native_finalization_selected()?,"native finalization not cold selected")?;
        Ok(&self.payload["policyCanaryFinalizationPolicy"])
    }
    pub fn finalization_assignment(&self,canary:&str)->Result<(&Value,String),String> {
        let policy=self.finalization_policy()?;let binding=self.binding(canary)?;
        let matches=policy["assignments"].as_array().ok_or("finalization assignments")?.iter()
            .filter(|item|item["canaryId"]==canary && item["instanceId"]==self.config.instance_id
                && item["canaryAssignmentSha256"]==binding.canary_assignment_sha256 && item["canaryBootId"]==binding.canary_boot_id).collect::<Vec<_>>();
        require(matches.len()==1,"finalization independent assignment missing/ambiguous")?;
        Ok((matches[0],crate::sha256_prefixed(&ascii(matches[0])?)))
    }
    pub fn heartbeat_assignment(&self,canary:&str)->Result<(&Value,String),String> {
        require(self.config.api_version=="serverware.nativeCanaryDurableDelivery/v2","v1 heartbeat requires its original cold profile")?;
        require(self.native_cumulative_selected()?,"native heartbeat not cold selected")?;
        let binding=self.binding(canary)?;
        let policy=&self.payload["policyCanaryHeartbeatPolicy"];
        let matches:Vec<_>=policy["assignments"].as_array().ok_or("heartbeat assignments")?.iter()
            .filter(|item|item["canaryId"]==canary && item["instanceId"]==self.config.instance_id
                && item["canaryAssignmentSha256"]==binding.canary_assignment_sha256 && item["canaryBootId"]==binding.canary_boot_id).collect();
        require(matches.len()==1,"heartbeat has no unique independent assignment")?;
        Ok((matches[0],crate::sha256_prefixed(&ascii(matches[0])?)))
    }
    pub fn heartbeat_policy(&self)->Result<&Value,String> {
        require(self.config.api_version=="serverware.nativeCanaryDurableDelivery/v2","v1 heartbeat requires its original cold profile")?;
        require(self.native_cumulative_selected()?,"heartbeat profile absent")?;
        Ok(&self.payload["policyCanaryHeartbeatPolicy"])
    }
    pub fn operation_deadline(&self,original:u64,include_intake:bool)->Result<u64,String>{
        self.check()?;let epoch=crate::native_canary_evidence_v1::now_epoch()?;let boot=crate::native_canary_evidence_v1::now_boot()?;
        let mut deadline=original;
        for field in if include_intake {&["policyCanaryIntakePolicy","policyCanaryDeliveryPolicy"][..]}else{&["policyCanaryDeliveryPolicy"][..]} {
            let policy=&self.payload[*field];let remaining=number(policy,"expiresAtEpochNs")?.checked_sub(epoch).ok_or("canary policy expired")?;
            let allowance=number(policy,"operationMaxSeconds")?.checked_mul(1_000_000_000).ok_or("canary policy interval")?;
            deadline=deadline.min(boot.checked_add(remaining.min(allowance)).ok_or("canary original deadline overflow")?);
        }require(boot<deadline,"canary original operation expired")?;Ok(deadline)
    }
    pub fn binding(&self,canary:&str)->Result<&CanaryBinding,String> {
        self.check()?; self.config.canaries.iter().find(|v|v.canary_id==canary).ok_or("canary not cold assigned".into())
    }
    pub fn check(&self)->Result<(),String> {
        let now=crate::native_canary_evidence_v1::now_epoch()?;
        require(self.pid==std::process::id(),"canary authority owner process changed")?;
        if self.config.api_version=="serverware.nativeCanaryDurableDelivery/v2" {
            crate::native_canary_heartbeat_v1::validate_policy(&self.payload["policyCanaryHeartbeatPolicy"],&self.config.deployment_id,now)?;
        }
        if self.config.api_version=="serverware.nativeCanaryDurableDelivery/v3" {
            crate::native_canary_finalization_v1::validate_policy(&self.payload["policyCanaryFinalizationPolicy"],&self.config.deployment_id,now)?;
        }
        for (field,schema) in [("policyCanaryIntakePolicy","serverware.policyCanaryIntakeAuthorityPolicy/v2"),
            ("policyCanaryDeliveryPolicy","serverware.policyCanaryDeliveryAuthorityPolicy/v1")] {
            let value=&self.payload[field];
            exact(value,if field=="policyCanaryIntakePolicy" {&["schema","deploymentId","issuedAtEpochNs","expiresAtEpochNs","operationMaxSeconds","limits","trustRoots","assignments"]}
                else{&["schema","deploymentId","issuedAtEpochNs","expiresAtEpochNs","operationMaxSeconds","limits","trustRoots","assignments","historicalTrustRoots","historicalAssignments","recoveryAssociations"]})?;
            require(value["schema"]==schema && value["deploymentId"]==self.config.deployment_id
                && number(value,"issuedAtEpochNs")?<number(value,"expiresAtEpochNs")?
                && (field=="policyCanaryIntakePolicy" || number(value,"issuedAtEpochNs")?<=now && now<number(value,"expiresAtEpochNs")?)
                && number(value,"expiresAtEpochNs")?-number(value,"issuedAtEpochNs")?<=86_400_000_000_000
                && (1..=30).contains(&number(value,"operationMaxSeconds")?),"canary current purpose policy absent/expired")?;
        }
        require(self.payload["policyCanaryDeliveryPolicy"]["limits"]==serde_json::json!({"httpOriginalBytes":1245184,"argumentBytes":3145728,
            "completionOriginalBytes":786432,"responseBytes":6291456,"partBytes":65536,"parts":20,"queryRows":48,"mutations":24,"workUnits":8192}),"delivery signed limits differ from source")?;
        for role in ["verifier","planner"] {
            let operations=self.payload["roles"][role]["enabledOperations"].as_array().ok_or("canary authority enabled operations")?;
            for operation in [Operation::Prepare,Operation::Recover,Operation::Claim] {
                require(operations.iter().any(|v|v==operation.label()),"canary phase not independently enabled")?;
            }
            require(operations.iter().any(|v|v=="policy.canary.evidence-intake"),"canary intake not independently enabled")?;
        }
        Ok(())
    }
    pub fn require_sender(&self,statement:&Value,delivery:bool)->Result<(),String> {
        self.check()?;
        let policy=&self.payload[if delivery {"policyCanaryDeliveryPolicy"} else {"policyCanaryIntakePolicy"}];
        let now=crate::native_canary_evidence_v1::now_epoch()?;
        require(number(policy,"issuedAtEpochNs")?<=now && now<number(policy,"expiresAtEpochNs")?,"canary selected action policy is not current")?;
        let assignment=assignment(policy,text(statement,"purposeAssignmentSha256")?)?;
        require(statement["deploymentId"]==self.config.deployment_id && statement["instanceId"]==self.config.instance_id,"canary sender deployment/instance")?;
        for name in ["holderId","bootId","keyId","controlPlaneResponseSigningKeyId","policyHash","canaryId","instanceId","canaryAssignmentSha256","canaryBootId"] {
            require(statement[name]==assignment[name],"canary actual native sender differs from signed assignment")?;
        }
        require(statement["dataPlaneBinarySha256"]==assignment["expectedBinaryDigest"]
            && number(statement,"expiresAtEpochNs")?<=number(policy,"expiresAtEpochNs")?
            && number(statement,"expiresAtEpochNs")?.checked_sub(number(statement,"issuedAtEpochNs")?).is_some_and(|v|v<=number(policy,"operationMaxSeconds").unwrap_or(0)*1_000_000_000),
            "canary source or purpose lifetime changed")
    }
}
fn assignment<'a>(policy:&'a Value,digest:&str)->Result<&'a Value,String> {
    let values=policy["assignments"].as_array().ok_or("canary signed assignments")?;
    require((1..=32).contains(&values.len()),"canary assignment count")?;
    let mut found=None;
    for value in values { if crate::sha256_prefixed(&ascii(value)?)==digest {
        require(found.is_none(),"canary repeated assignment")?; found=Some(value);
    }}
    found.ok_or("canary assignment not independently admitted".into())
}
