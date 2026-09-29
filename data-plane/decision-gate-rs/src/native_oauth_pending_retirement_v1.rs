//! Separate staged-pending retirement preparations from the actual helper.
//! A pending ID is not a credential, refresh work item, or currentness root.
//! These public data checks do not replace independent grant/receipt admission.
use crate::native_currentness_v1 as current;
use crate::native_oauth_refresh_v1::{ensure, sha};
use crate::native_response_profile_v1::canonical_ascii_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const CHANNEL: &str = "serverware.nativeOAuthPendingRetirementChannel/v1";
pub const TLS: &str = "serverware.nativeOAuthPendingRetirementTls/v1";
pub const SCHEMA: &str = "serverware.nativeOAuthPendingRetirementStatement/v1";
pub const ATTESTATION_DOMAIN: &[u8] = b"serverware/native-oauth-pending-retirement-attestation/v1\0";
pub const HTTP_REQUEST: &str = "serverware.nativeOAuthPendingRetirementRequest/v1";
pub const HTTP_RESPONSE: &str = "serverware.nativeOAuthPendingRetirementResponse/v1";
pub const HTTP_PATH: &str = "/api/data-plane/oauth-pending-retirement";

fn fields(value: &Value, names: &[&str]) -> Result<(), String> {
    ensure(value.as_object().is_some_and(|v| v.len() == names.len()
        && names.iter().all(|name| v.contains_key(*name))), "pending retirement fields differ")
}
fn original(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let raw = URL_SAFE_NO_PAD.decode(value).map_err(|_|"pending retirement original encoding")?;
    ensure(!raw.is_empty() && raw.len() <= maximum && URL_SAFE_NO_PAD.encode(&raw) == value,
        "pending retirement original bound")?;
    Ok(raw)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Application {
    pub enrollment_original: String, pub material: Value, pub tls_roots_pem: String, pub pending_ids: Vec<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Target { pub authorization_original: String, pub historical_root_original: String, pub recovery: bool }
impl Target {
    pub(crate) fn grant(&self) -> Result<Value, String> {
        let raw = original(&self.authorization_original, 65536)?;
        let value = crate::native_oauth_refresh_v1::response_document(&raw)?;
        fields(&value, &["schema","payload","signatureBase64Url"])?;
        ensure(canonical_ascii_bytes(&value)? == raw
            && value["schema"] == "serverware.signedOAuthMeasuredPendingRetirementAuthorization/v1",
            "pending retirement signed grant family differs")?;
        let grant = &value["payload"];
        fields(grant, &["schema","sourceRevision","purpose","authorizationId","configurationDigest","deploymentId",
            "exchangeId","exchangeRowSha256","custodyRowSha256","pendingId","initialPendingRowSha256",
            "currentPendingRowSha256","stageArgumentsSha256","enrollmentSha256","historicalEnrollmentRootSpkiSha256",
            "tokenEnvelopeSha256","tokenSecretSha256","providerId","clientId","clientMaterialSha256","providerConfiguration",
            "tokenPurposes","familyScope","affectedLineages","applicationMaterialSha256","providerTlsRootSha256",
            "holderId","reason","issuedAtEpochNs","expiresAtEpochNs"])?;
        ensure(grant["schema"] == "serverware.oauthMeasuredPendingRetirementAuthorization/v1"
            && grant["purpose"] == "measured-oauth-staged-pending-family-retirement"
            && matches!(grant["reason"].as_str(), Some("cancelled" | "expired" | "rejected")),
            "pending retirement purpose differs")?;
        for name in ["authorizationId","exchangeId","pendingId"] {
            ensure(grant[name].as_str().is_some_and(current::uuid), "pending retirement ID spelling")?;
        }
        let signature = original(value["signatureBase64Url"].as_str().ok_or("pending grant signature absent")?, 64)?;
        ensure(signature.len() == 64, "pending grant signature bound")?;
        let lineages = grant["affectedLineages"].as_array().ok_or("pending grant lineages absent")?;
        ensure(lineages.len() <= 24, "pending retirement lineage capacity exceeded")?;
        let mut previous = None;
        for lineage in lineages {
            fields(lineage, &["credentialId","credentialVersion","credentialRowSha256","generationRowSha256"])?;
            let id = lineage["credentialId"].as_str().ok_or("affected credential ID absent")?;
            ensure(current::uuid(id) && previous.is_none_or(|before| before < id)
                && lineage["credentialVersion"].as_u64().is_some_and(|v| v > 0 && v <= i64::MAX as u64),
                "affected lineage order or version differs")?;
            for name in ["credentialRowSha256","generationRowSha256"] {
                ensure(lineage[name].as_str().is_some_and(current::digest), "affected lineage pin absent")?;
            }
            previous = Some(id);
        }
        Ok(grant.clone())
    }
    pub fn pending_id(&self) -> Result<String, String> {
        Ok(self.grant()?["pendingId"].as_str().ok_or("pending ID absent")?.to_owned())
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
        ensure(self.api_version == "serverware.nativeOAuthPendingRetirementConfiguration/v1"
            && !self.source_revision.is_empty() && self.source_revision.len() <= 128
            && current::digest(&self.authority_root_spki_sha256) && current::digest(&self.control_plane_configuration_digest)
            && current::identifier(&self.deployment_id) && self.deployment_id.len() <= 128
            && self.instance_id.starts_with("spiffe://") && self.instance_id.len() <= 4096
            && !self.instance_id.chars().any(char::is_control)
            && !self.applications.is_empty() && self.applications.len() <= 2
            && !self.targets.is_empty() && self.targets.len() <= 16, "pending retirement cold configuration differs")?;
        let raw = current::bytes32(&self.authority_root_public_key)?;
        let mut spki = vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]; spki.extend(raw);
        ensure(sha(&spki) == self.authority_root_spki_sha256, "pending retirement root pin differs")?;
        let mut assigned = BTreeSet::new();
        for (provider, app) in &self.applications {
            ensure(matches!(provider.as_str(), "google" | "x") && !app.pending_ids.is_empty()
                && app.pending_ids.len() <= 64 && app.pending_ids.windows(2).all(|pair| pair[0] < pair[1])
                && !app.tls_roots_pem.is_empty() && app.tls_roots_pem.len() <= 128 * 1024
                && app.tls_roots_pem.is_ascii() && app.material.is_object(), "pending application inventory differs")?;
            original(&app.enrollment_original, 32768)?;
            for id in &app.pending_ids { ensure(current::uuid(id) && assigned.insert(id.clone()), "pending application ID repeats")?; }
        }
        let mut selected = BTreeSet::new();
        for target in &self.targets {
            let grant = target.grant()?; let id = target.pending_id()?;
            let app = self.applications.get(grant["providerId"].as_str().ok_or("pending provider absent")?)
                .ok_or("pending provider application absent")?;
            ensure(selected.insert(id.clone()) && app.pending_ids.contains(&id)
                && grant["enrollmentSha256"] == sha(&original(&app.enrollment_original, 32768)?)
                && grant["deploymentId"] == self.deployment_id
                && (target.recovery || grant["configurationDigest"] == self.control_plane_configuration_digest
                    && grant["sourceRevision"] == self.source_revision), "pending target association differs")?;
            original(&target.historical_root_original, 4096)?;
        }
        ensure(canonical_ascii_bytes(self)?.len() <= 1024 * 1024, "pending retirement configuration bound")
    }
    pub fn target(&self, id: &str) -> Result<&Target, String> {
        self.targets.iter().find(|v| v.pending_id().is_ok_and(|v| v == id))
            .ok_or_else(||"pending retirement target is not cold-selected".to_owned())
    }
}

/// Only the actual private broker reply constructor can prepare this purpose.
pub struct Prepared { arguments: Value, operation: String, issued: u64, expires: u64, config: Configuration }
pub struct Complete { pub pending_id: String, pub status: String }
pub enum Reply { Prepared(Prepared), Complete(Complete) }
impl Reply {
    pub(crate) fn parse(value: Value, config: &Configuration) -> Result<Self, String> {
        ensure(value["apiVersion"] == CHANNEL, "pending retirement helper channel differs")?;
        if value["phase"] == "prepared" {
            fields(&value, &["apiVersion","phase","operation","arguments","issuedAtEpochNs","expiresAtEpochNs"])?;
            let prepared = Prepared { arguments: value["arguments"].clone(), operation: value["operation"].as_str()
                .ok_or("pending retirement operation")?.to_owned(), issued: value["issuedAtEpochNs"].as_u64()
                .ok_or("pending issue time")?, expires: value["expiresAtEpochNs"].as_u64().ok_or("pending expiry")?, config: config.clone() };
            fields(&prepared.arguments, &["pending_id","authorization_original","enrollment_original","historical_root_original",
                "control_plane_configuration_digest","assignment_original","request"])?;
            let phase = prepared.operation.strip_prefix("oauth.measured-pending-retirement.").ok_or("pending operation purpose")?;
            let request_fields: &[&str] = match phase {
                "inspect" | "recover" => &["issuedAtEpochNs","expiresAtEpochNs"],
                "claim" => &["ownerNonceSha256","currentnessBarriers"],
                "contact" => &["journalRowSha256","ownerNonce","tokenPurpose","contactRequestSha256"],
                "finish" => &["journalRowSha256","ownerNonce","attemptRowSha256","tokenPurpose","transportOriginal"],
                _ => return Err("pending retirement phase differs".to_owned()),
            };
            fields(&prepared.arguments["request"], request_fields)?;
            let id = prepared.arguments["pending_id"].as_str().ok_or("pending target absent")?;
            let target = config.target(id)?; let grant = target.grant()?;
            let app = config.applications.get(grant["providerId"].as_str().ok_or("pending provider absent")?)
                .ok_or("pending application absent")?;
            ensure(prepared.expires > prepared.issued && prepared.expires - prepared.issued <= 30_000_000_000
                && prepared.arguments["authorization_original"] == target.authorization_original
                && prepared.arguments["enrollment_original"] == app.enrollment_original
                && prepared.arguments["historical_root_original"] == target.historical_root_original
                && prepared.arguments["control_plane_configuration_digest"] == config.control_plane_configuration_digest
                && (phase == "recover") == target.recovery, "pending preparation original association differs")?;
            if matches!(phase, "inspect" | "recover") {
                ensure(prepared.arguments["request"]["issuedAtEpochNs"] == prepared.issued
                    && prepared.arguments["request"]["expiresAtEpochNs"] == prepared.expires, "pending preparation window differs")?;
            }
            Ok(Self::Prepared(prepared))
        } else {
            fields(&value, &["apiVersion","phase","pendingId","status"])?;
            ensure(value["phase"] == "complete", "pending completion phase differs")?;
            let id = value["pendingId"].as_str().ok_or("pending completion target")?.to_owned(); config.target(&id)?;
            let status = value["status"].as_str().ok_or("pending completion status")?.to_owned();
            ensure(matches!(status.as_str(), "no-local-claim" | "outcome-unknown" | "unknown" | "observed-accepted" | "observed-rejected"),
                "pending completion status invalid")?;
            Ok(Self::Complete(Complete { pending_id: id, status }))
        }
    }
}
impl Prepared {
    pub fn operation(&self) -> &str { &self.operation }
    pub fn pending_id(&self) -> &str { self.arguments["pending_id"].as_str().expect("closed pending target") }
    pub fn phase_key(&self) -> Result<String, String> {
        let purpose = self.arguments["request"]["tokenPurpose"].as_str().unwrap_or("");
        ensure(matches!(purpose, "" | "access_token" | "refresh_token"), "pending token purpose differs")?;
        Ok(format!("{}:{purpose}", self.operation))
    }
    pub(crate) fn statement(&self, boot: &str, key: &str, cp_key: &str, policy: &str, binary: &str) -> Result<Statement, String> {
        let target = self.config.target(self.pending_id())?; let grant = target.grant()?;
        let holder = current::holder_id(boot, key)?;
        if !target.recovery {
            ensure(grant["holderId"] == holder
                && grant["issuedAtEpochNs"].as_u64().is_some_and(|v| v <= self.issued)
                && grant["expiresAtEpochNs"].as_u64().is_some_and(|v| self.expires <= v),
                "pending preparation owner or grant window differs")?;
        }
        let mut challenge = [0u8;32];
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new().fill(&mut challenge).map_err(|_|"pending retirement entropy")?;
        Ok(Statement(json!({"apiVersion":SCHEMA,"phase":self.operation.rsplit('.').next().ok_or("pending phase")?,
            "holderId":holder,"bootId":boot,"keyId":key,"controlPlaneResponseSigningKeyId":cp_key,
            "deploymentId":self.config.deployment_id,"instanceId":self.config.instance_id,"providerId":grant["providerId"],
            "enrollmentSha256":grant["enrollmentSha256"],"pendingId":self.pending_id(),
            "authorizationSha256":sha(&original(&target.authorization_original, 65536)?),
            "inputSha256":sha(&canonical_ascii_bytes(&self.arguments)?),"challenge":URL_SAFE_NO_PAD.encode(challenge),
            "policyHash":policy,"dataPlaneBinarySha256":binary,"issuedAtEpochNs":self.issued,"expiresAtEpochNs":self.expires})))
    }
    pub fn wire(&self, evidence: Value) -> Result<Value, String> {
        ensure(evidence["statement"]["apiVersion"] == SCHEMA
            && evidence["statement"]["inputSha256"] == sha(&canonical_ascii_bytes(&self.arguments)?), "pending evidence original differs")?;
        let mut arguments = self.arguments.clone(); arguments.as_object_mut().ok_or("pending arguments")?.insert("evidence".to_owned(), evidence);
        let value = json!({"apiVersion":HTTP_REQUEST,"operation":self.operation,"arguments":arguments});
        ensure(canonical_ascii_bytes(&value)?.len() <= 1024 * 1024, "pending signed request bound")?;
        Ok(value)
    }
}
pub(crate) struct Statement(pub(crate) Value);
impl Statement {
    pub(crate) fn validate(&self, now: u64) -> Result<(), String> {
        let issued = self.0["issuedAtEpochNs"].as_u64().ok_or("pending statement issue")?;
        let expires = self.0["expiresAtEpochNs"].as_u64().ok_or("pending statement expiry")?;
        ensure(issued <= now && now < expires && expires - issued <= 30_000_000_000, "pending original expired")
    }
    pub(crate) fn canonical(&self) -> Result<Vec<u8>, String> { canonical_ascii_bytes(&self.0) }
    pub(crate) fn preimage(&self) -> Result<Vec<u8>, String> {
        let mut value = SCHEMA.as_bytes().to_vec(); value.push(0); value.extend(self.canonical()?); Ok(value)
    }
}
