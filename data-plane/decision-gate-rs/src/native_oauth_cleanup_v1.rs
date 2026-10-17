//! Sealed preparations from the actual broker, distinct from refresh issuance.
use crate::native_currentness_v1 as current;
use crate::native_oauth_refresh_v1::{ensure, sha, Application};
use crate::native_response_profile_v1::canonical_ascii_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const CHANNEL: &str = "catchplate.nativeOAuthRefreshCleanupChannel/v1";
pub const SCHEMA: &str = "catchplate.nativeOAuthRefreshCleanupStatement/v1";
pub const ATTESTATION_DOMAIN: &[u8] = b"catchplate/native-oauth-refresh-cleanup-attestation/v1\0";
pub const HTTP_REQUEST: &str = "catchplate.nativeOAuthRefreshCleanupRequest/v1";
pub const HTTP_RESPONSE: &str = "catchplate.nativeOAuthRefreshCleanupResponse/v1";

pub fn response_document(raw: &[u8]) -> Result<Value, String> {
    crate::native_oauth_refresh_v1::response_document(raw)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Target { pub authorization_original: String, pub historical_root_original: String, pub recovery: bool }
impl Target {
    pub(crate) fn grant(&self) -> Result<Value, String> {
        let raw = URL_SAFE_NO_PAD.decode(&self.authorization_original).map_err(|_|"cleanup grant encoding")?;
        ensure(!raw.is_empty() && raw.len() <= 65536 && URL_SAFE_NO_PAD.encode(&raw) == self.authorization_original, "cleanup grant bound")?;
        let value = crate::native_oauth_refresh_v1::response_document(&raw)?;
        ensure(canonical_ascii_bytes(&value)? == raw && value.as_object().is_some_and(|v| v.len() == 3)
            && value["schema"] == "catchplate.signedOAuthMeasuredRefreshCleanupAuthorization/v1"
            && value["payload"]["schema"] == "catchplate.oauthMeasuredRefreshCleanupAuthorization/v1"
            && value["payload"]["purpose"] == "measured-oauth-refresh-family-retirement", "cleanup grant family differs")?;
        let signature = value["signatureBase64Url"].as_str().ok_or("cleanup signature absent")?;
        let bytes = URL_SAFE_NO_PAD.decode(signature).map_err(|_|"cleanup signature encoding")?;
        ensure(bytes.len() == 64 && URL_SAFE_NO_PAD.encode(bytes) == signature, "cleanup signature bound")?;
        Ok(value["payload"].clone())
    }
    pub fn work_id(&self) -> Result<String, String> {
        let grant = self.grant()?;
        let id = grant["workId"].as_str().ok_or("cleanup work ID absent")?;
        ensure(current::uuid(id), "cleanup work ID spelling")?; Ok(id.to_owned())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub api_version: String, pub source_revision: String, pub authority_root_public_key: String,
    pub authority_root_spki_sha256: String, pub control_plane_configuration_digest: String,
    pub deployment_id: String, pub instance_id: String, pub applications: BTreeMap<String, Application>, pub targets: Vec<Target>,
}
impl Configuration {
    pub fn validate(&self) -> Result<(), String> {
        ensure(self.api_version == "catchplate.nativeOAuthRefreshCleanupConfiguration/v1" && !self.targets.is_empty()
            && self.targets.len() <= 16, "cleanup cold configuration family or bound")?;
        // Reuse only closed public application data predicates, never the
        // refresh permission, target list, helper owner or statement type.
        crate::native_oauth_refresh_v1::Configuration {
            api_version: "catchplate.nativeOAuthRefreshConfiguration/v1".to_owned(), source_revision: self.source_revision.clone(),
            authority_root_public_key: self.authority_root_public_key.clone(), authority_root_spki_sha256: self.authority_root_spki_sha256.clone(),
            control_plane_configuration_digest: self.control_plane_configuration_digest.clone(), deployment_id: self.deployment_id.clone(),
            instance_id: self.instance_id.clone(), limits: crate::native_oauth_refresh_v1::Limits {
                due_within_seconds: 60, operation_max_seconds: 30, revocation_capacity: 64 },
            applications: self.applications.clone(), recovery_targets: Vec::new(),
        }.validate()?;
        let mut seen = BTreeSet::new();
        for target in &self.targets {
            let grant = target.grant()?;
            let id = target.work_id()?;
            let provider = grant["providerId"].as_str().ok_or("cleanup provider absent")?;
            let app = self.applications.get(provider).ok_or("cleanup application absent")?;
            let credential = grant["credentialId"].as_str().ok_or("cleanup credential absent")?;
            ensure(seen.insert(id) && app.credential_ids.iter().any(|v| v == credential)
                && grant["deploymentId"] == self.deployment_id
                && (target.recovery || grant["configurationDigest"] == self.control_plane_configuration_digest
                    && grant["sourceRevision"] == self.source_revision),
                "cleanup target original association differs")?;
            let root = URL_SAFE_NO_PAD.decode(&target.historical_root_original).map_err(|_|"cleanup historical root encoding")?;
            ensure(!root.is_empty() && root.len() <= 4096 && URL_SAFE_NO_PAD.encode(root) == target.historical_root_original,
                "cleanup historical root bound")?;
        }
        ensure(canonical_ascii_bytes(self)?.len() <= 1024 * 1024, "cleanup cold configuration bound")
    }
    pub fn target(&self, id: &str) -> Result<&Target, String> {
        self.targets.iter().find(|v| v.work_id().is_ok_and(|v| v == id)).ok_or_else(||"cleanup work is not cold-selected".to_owned())
    }
}

pub struct Prepared { arguments: Value, operation: String, issued: u64, expires: u64, config: Configuration }
pub struct Complete { pub work_id: String, pub status: String }
pub enum Reply { Prepared(Prepared), Complete(Complete) }
impl Reply {
    pub(crate) fn parse(value: Value, config: &Configuration) -> Result<Self, String> {
        ensure(value["apiVersion"] == CHANNEL, "cleanup helper channel differs")?;
        let fields = value.as_object().ok_or("cleanup reply is not an object")?;
        if value["phase"] == "prepared" {
            ensure(fields.len() == 6 && ["apiVersion","phase","operation","arguments","issuedAtEpochNs","expiresAtEpochNs"]
                .iter().all(|v| fields.contains_key(*v)), "cleanup preparation fields differ")?;
            let prepared = Prepared { arguments: value["arguments"].clone(), operation: value["operation"].as_str().ok_or("cleanup operation")?.to_owned(),
                issued: value["issuedAtEpochNs"].as_u64().ok_or("cleanup issue time")?, expires: value["expiresAtEpochNs"].as_u64().ok_or("cleanup expiry")?, config: config.clone() };
            ensure(matches!(prepared.operation.as_str(), "oauth.measured-refresh-cleanup.inspect" | "oauth.measured-refresh-cleanup.claim"
                | "oauth.measured-refresh-cleanup.contact" | "oauth.measured-refresh-cleanup.finish" | "oauth.measured-refresh-cleanup.recover")
                && prepared.arguments.as_object().is_some_and(|v| v.len() == 7 && ["work_id","authorization_original","enrollment_original",
                    "historical_root_original","control_plane_configuration_digest","assignment_original","request"].iter().all(|name|v.contains_key(*name)))
                && prepared.expires > prepared.issued && prepared.expires - prepared.issued <= 30_000_000_000,
                "cleanup preparation is not closed")?;
            let id = prepared.arguments["work_id"].as_str().ok_or("cleanup work absent")?;
            let target = config.target(id)?;
            ensure(prepared.arguments["authorization_original"] == target.authorization_original
                && prepared.arguments["historical_root_original"] == target.historical_root_original
                && prepared.arguments["control_plane_configuration_digest"] == config.control_plane_configuration_digest
                && (prepared.operation == "oauth.measured-refresh-cleanup.recover") == target.recovery,
                "cleanup preparation selected another original or recovery profile")?;
            Ok(Self::Prepared(prepared))
        } else {
            ensure(fields.len() == 4 && ["apiVersion","phase","workId","status"].iter().all(|v|fields.contains_key(*v))
                && value["phase"] == "complete", "cleanup observation fields differ")?;
            let id = value["workId"].as_str().ok_or("cleanup observation work")?.to_owned(); config.target(&id)?;
            let status = value["status"].as_str().ok_or("cleanup observation status")?.to_owned();
            ensure(matches!(status.as_str(), "no-local-claim" | "outcome-unknown" | "unknown" | "observed-accepted" | "observed-rejected"),
                "cleanup observation status invalid")?;
            Ok(Self::Complete(Complete { work_id: id, status }))
        }
    }
}
impl Prepared {
    pub fn operation(&self) -> &str { &self.operation }
    pub fn work_id(&self) -> &str { self.arguments["work_id"].as_str().expect("closed cleanup work") }
    pub fn phase_key(&self) -> Result<String, String> {
        let purpose = self.arguments["request"]["tokenPurpose"].as_str().unwrap_or("");
        ensure(matches!(purpose, "" | "access_token" | "refresh_token"), "cleanup token purpose")?;
        Ok(format!("{}:{purpose}", self.operation))
    }
    pub(crate) fn statement(&self, boot: &str, key: &str, cp_key: &str, policy: &str, binary: &str) -> Result<Statement, String> {
        let target = self.config.target(self.work_id())?; let grant = target.grant()?;
        let mut challenge = [0u8;32];
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new().fill(&mut challenge).map_err(|_|"cleanup entropy")?;
        let raw = URL_SAFE_NO_PAD.decode(&target.authorization_original).map_err(|_|"cleanup original encoding")?;
        Ok(Statement(json!({"apiVersion":SCHEMA,"phase":self.operation.rsplit('.').next().ok_or("cleanup phase")?,
            "holderId":current::holder_id(boot,key)?,"bootId":boot,"keyId":key,"controlPlaneResponseSigningKeyId":cp_key,
            "deploymentId":self.config.deployment_id,"instanceId":self.config.instance_id,"providerId":grant["providerId"],
            "enrollmentSha256":grant["enrollmentSha256"],"credentialId":grant["credentialId"],"credentialVersion":grant["credentialVersion"],
            "workId":self.work_id(),"authorizationSha256":sha(&raw),"inputSha256":sha(&canonical_ascii_bytes(&self.arguments)?),
            "challenge":URL_SAFE_NO_PAD.encode(challenge),"policyHash":policy,"dataPlaneBinarySha256":binary,
            "issuedAtEpochNs":self.issued,"expiresAtEpochNs":self.expires})))
    }
    pub fn wire(&self, evidence: Value) -> Result<Value, String> {
        ensure(evidence["statement"]["inputSha256"] == sha(&canonical_ascii_bytes(&self.arguments)?), "cleanup evidence original differs")?;
        let mut arguments = self.arguments.clone(); arguments.as_object_mut().ok_or("cleanup arguments")?.insert("evidence".to_owned(), evidence);
        Ok(json!({"apiVersion":HTTP_REQUEST,"operation":self.operation,"arguments":arguments}))
    }
}
pub(crate) struct Statement(pub(crate) Value);
impl Statement {
    pub(crate) fn validate(&self, now: u64) -> Result<(), String> {
        let issued = self.0["issuedAtEpochNs"].as_u64().ok_or("cleanup issue")?;
        let expires = self.0["expiresAtEpochNs"].as_u64().ok_or("cleanup expiry")?;
        ensure(issued <= now && now < expires && expires - issued <= 30_000_000_000, "cleanup original expired")
    }
    pub(crate) fn canonical(&self) -> Result<Vec<u8>, String> { canonical_ascii_bytes(&self.0) }
    pub(crate) fn preimage(&self) -> Result<Vec<u8>, String> {
        let mut value = SCHEMA.as_bytes().to_vec(); value.push(0); value.extend(self.canonical()?); Ok(value)
    }
}
