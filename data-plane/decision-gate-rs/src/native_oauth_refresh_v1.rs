//! Dedicated measured refresh preparations from the actual private broker.
//! Public ciphertext configuration is not issuance permission; the helper and
//! both authority roles independently admit the signed purpose assignment.
use crate::native_currentness_v1 as current;
use crate::native_response_profile_v1::canonical_ascii_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[path = "native_verifier/json.rs"]
mod json;

pub fn response_document(raw: &[u8]) -> Result<Value, String> { json::parse(raw, 8 * 1024 * 1024) }

pub const CHANNEL: &str = "catchplate.nativeOAuthRefreshChannel/v1";
pub const SCHEMA: &str = "catchplate.nativeOAuthRefreshStatement/v1";
pub const ATTESTATION_DOMAIN: &[u8] = b"catchplate/native-oauth-refresh-attestation/v1\0";
pub const SIGN_OPERATION: &str = "nativeOAuthRefresh.sign/v1";
pub const HTTP_REQUEST: &str = "catchplate.nativeOAuthRefreshRequest/v1";
pub const HTTP_RESPONSE: &str = "catchplate.nativeOAuthRefreshResponse/v1";

pub(crate) fn ensure(value: bool, error: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(error.to_owned()) }
}
pub(crate) fn sha(raw: &[u8]) -> String { format!("sha256:{}", hex::encode(Sha256::digest(raw))) }

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Limits { pub due_within_seconds: u64, pub operation_max_seconds: u64, pub revocation_capacity: u64 }
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Application {
    pub enrollment_original: String, pub material: Value, pub tls_roots_pem: String, pub credential_ids: Vec<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct RecoveryTarget { pub credential_id: String, pub credential_version: u64 }
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub api_version: String, pub source_revision: String, pub authority_root_public_key: String,
    pub authority_root_spki_sha256: String, pub control_plane_configuration_digest: String,
    pub deployment_id: String, pub instance_id: String, pub limits: Limits,
    pub applications: BTreeMap<String, Application>, pub recovery_targets: Vec<RecoveryTarget>,
}
impl Configuration {
    pub fn validate(&self) -> Result<(), String> {
        ensure(self.api_version == "catchplate.nativeOAuthRefreshConfiguration/v1"
            && current::digest(&self.authority_root_spki_sha256) && current::digest(&self.control_plane_configuration_digest)
            && current::identifier(&self.deployment_id) && self.deployment_id.len() <= 128
            && self.instance_id.starts_with("spiffe://") && self.instance_id.len() <= 4096
            && !self.instance_id.chars().any(char::is_control)
            && self.limits.due_within_seconds == 60 && self.limits.operation_max_seconds == 30
            && self.limits.revocation_capacity == 64 && !self.applications.is_empty() && self.applications.len() <= 2,
            "native measured refresh cold purpose is invalid")?;
        let raw = current::bytes32(&self.authority_root_public_key)?;
        let mut spki = vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]; spki.extend(raw);
        ensure(sha(&spki) == self.authority_root_spki_sha256, "refresh root SPKI pin differs")?;
        let mut seen = BTreeSet::new();
        for (provider, app) in &self.applications {
            ensure(matches!(provider.as_str(), "google" | "x") && !app.credential_ids.is_empty()
                && app.credential_ids.len() <= 64 && app.credential_ids.windows(2).all(|pair| pair[0] < pair[1])
                && !app.tls_roots_pem.is_empty() && app.tls_roots_pem.len() <= 128 * 1024
                && app.tls_roots_pem.is_ascii() && app.material.is_object(), "refresh application inventory differs")?;
            let raw = URL_SAFE_NO_PAD.decode(&app.enrollment_original).map_err(|_| "refresh enrollment encoding")?;
            ensure(!raw.is_empty() && raw.len() <= 32768 && URL_SAFE_NO_PAD.encode(raw) == app.enrollment_original,
                "refresh original enrollment bound")?;
            for id in &app.credential_ids { ensure(current::uuid(id) && seen.insert(id.clone()), "refresh credential assignment repeats")?; }
        }
        ensure(self.recovery_targets.len() <= 64, "refresh recovery inventory bound")?;
        let mut recovery = BTreeSet::new();
        for target in &self.recovery_targets {
            ensure(seen.contains(&target.credential_id) && target.credential_version > 0 && target.credential_version < i64::MAX as u64
                && recovery.insert((target.credential_id.clone(), target.credential_version)), "refresh recovery target differs")?;
        }
        ensure(canonical_ascii_bytes(self)?.len() <= 1024 * 1024, "refresh configuration bound")
    }
    pub fn contains(&self, id: &str) -> bool { self.applications.values().any(|app| app.credential_ids.iter().any(|v| v == id)) }
}

/// Only the private helper's bounded reply constructor can create this type.
/// The gate cannot relabel a response-family statement as a refresh request.
pub struct Prepared { arguments: Value, operation: String, issued: u64, expires: u64, config: Configuration }
pub struct Complete { pub credential_id: String, pub credential_version: u64, pub status: String }
pub enum Reply { Prepared(Prepared), Complete(Complete) }
impl Reply {
    pub(crate) fn parse(value: Value, config: &Configuration) -> Result<Self, String> {
        ensure(value["apiVersion"] == CHANNEL, "refresh helper channel differs")?;
        let object = value.as_object().ok_or("refresh helper object absent")?;
        if value["phase"] == "prepared" {
            ensure(object.len() == 6 && ["apiVersion","phase","operation","arguments","issuedAtEpochNs","expiresAtEpochNs"]
                .iter().all(|name| object.contains_key(*name)), "refresh preparation fields differ")?;
            let prepared = Prepared { arguments: value["arguments"].clone(), operation: value["operation"].as_str().ok_or("refresh operation")?.to_owned(),
                issued: value["issuedAtEpochNs"].as_u64().ok_or("refresh issue time")?, expires: value["expiresAtEpochNs"].as_u64().ok_or("refresh expiry")?, config: config.clone() };
            ensure(matches!(prepared.operation.as_str(), "oauth.measured-refresh.inspect" | "oauth.measured-refresh.claim" |
                "oauth.measured-refresh.capture" | "oauth.measured-refresh.commit" | "oauth.measured-refresh.recover")
                && prepared.arguments.as_object().is_some_and(|v| v.len() == 5 && ["credential_id","enrollment_original",
                    "control_plane_configuration_digest","assignment_original","request"].iter().all(|name| v.contains_key(*name)))
                && prepared.arguments["control_plane_configuration_digest"] == config.control_plane_configuration_digest
                && prepared.expires > prepared.issued && prepared.expires - prepared.issued <= 30_000_000_000,
                "refresh preparation is not closed")?;
            let id = prepared.arguments["credential_id"].as_str().ok_or("refresh credential")?;
            ensure(config.contains(id), "refresh helper selected an unassigned credential")?;
            Ok(Self::Prepared(prepared))
        } else {
            ensure(object.len() == 5 && ["apiVersion","phase","credentialId","credentialVersion","status"].iter().all(|name| object.contains_key(*name))
                && value["phase"] == "complete", "refresh terminal observation fields differ")?;
            let id = value["credentialId"].as_str().ok_or("refresh terminal credential")?.to_owned();
            let version = value["credentialVersion"].as_u64().ok_or("refresh terminal version")?;
            let status = value["status"].as_str().ok_or("refresh terminal status")?.to_owned();
            ensure(config.contains(&id) && version > 0 && version <= i64::MAX as u64
                && matches!(status.as_str(), "current" | "committed" | "observed-complete"), "refresh terminal observation invalid")?;
            Ok(Self::Complete(Complete { credential_id: id, credential_version: version, status }))
        }
    }
}
impl Prepared {
    pub fn operation(&self) -> &str { &self.operation }
    pub fn credential_id(&self) -> &str { self.arguments["credential_id"].as_str().expect("closed preparation") }
    pub(crate) fn statement(&self, boot: &str, key: &str, cp_key: &str, policy: &str, binary: &str) -> Result<Statement, String> {
        let provider = self.config.applications.iter().find(|(_, app)| app.credential_ids.iter().any(|v| v == self.credential_id())).ok_or("refresh assignment absent")?;
        let phase = self.operation.rsplit('.').next().ok_or("refresh phase")?;
        let version = if phase == "inspect" { 0 } else { self.arguments["request"]["expectedVersion"].as_u64().ok_or("refresh expected version")? };
        let original = URL_SAFE_NO_PAD.decode(self.arguments["enrollment_original"].as_str().ok_or("refresh enrollment")?).map_err(|_|"refresh enrollment encoding")?;
        let mut challenge = [0u8;32];
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new().fill(&mut challenge).map_err(|_|"refresh challenge entropy")?;
        let refresh_id = if version == 0 { Value::Null } else {
            // The exact stable UUID is generated by the helper and independently
            // recomputed by the writer; supplied here as a source-fixed UUIDv5.
            Value::String(uuid_v5(self.credential_id(), &format!("catchplate.oauthRefresh/v1:{version}"))?)
        };
        Ok(Statement(json!({"apiVersion":SCHEMA,"phase":phase,"holderId":current::holder_id(boot,key)?,"bootId":boot,"keyId":key,
            "controlPlaneResponseSigningKeyId":cp_key,"deploymentId":self.config.deployment_id,"instanceId":self.config.instance_id,
            "providerId":provider.0,"enrollmentSha256":sha(&original),"credentialId":self.credential_id(),"credentialVersion":version,
            "refreshId":refresh_id,"inputSha256":sha(&canonical_ascii_bytes(&self.arguments)?),"challenge":URL_SAFE_NO_PAD.encode(challenge),
            "policyHash":policy,"dataPlaneBinarySha256":binary,"issuedAtEpochNs":self.issued,"expiresAtEpochNs":self.expires})))
    }
    pub fn wire(&self, evidence: Value) -> Result<Value, String> {
        ensure(evidence["statement"]["inputSha256"] == sha(&canonical_ascii_bytes(&self.arguments)?), "refresh evidence original changed")?;
        let mut arguments = self.arguments.clone(); arguments.as_object_mut().ok_or("refresh arguments")?.insert("evidence".to_owned(), evidence);
        Ok(json!({"apiVersion":HTTP_REQUEST,"operation":self.operation,"arguments":arguments}))
    }
}

// UUIDv5 uses SHA-1 by definition, never as an authorization hash. The existing
// locked ring implementation avoids introducing a crypto/package dependency.
fn uuid_v5(namespace: &str, name: &str) -> Result<String, String> {
    ensure(current::uuid(namespace), "refresh UUID namespace")?;
    let mut bytes = hex::decode(namespace.replace('-', "")).map_err(|_|"refresh UUID bytes")?; bytes.extend(name.as_bytes());
    let hash = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &bytes);
    let mut out = hash.as_ref()[..16].to_vec(); out[6] = (out[6] & 15) | 80; out[8] = (out[8] & 63) | 128;
    let hex = hex::encode(out); Ok(format!("{}-{}-{}-{}-{}",&hex[..8],&hex[8..12],&hex[12..16],&hex[16..20],&hex[20..]))
}

pub(crate) struct Statement(pub(crate) Value);
impl Statement {
    pub(crate) fn validate(&self, now: u64) -> Result<(), String> {
        let issued = self.0["issuedAtEpochNs"].as_u64().ok_or("refresh statement issue")?;
        let expires = self.0["expiresAtEpochNs"].as_u64().ok_or("refresh statement expiry")?;
        ensure(issued <= now && now < expires && expires - issued <= 30_000_000_000, "refresh statement expired")
    }
    pub(crate) fn canonical(&self) -> Result<Vec<u8>, String> { canonical_ascii_bytes(&self.0) }
    pub(crate) fn preimage(&self) -> Result<Vec<u8>, String> {
        let mut value = SCHEMA.as_bytes().to_vec(); value.push(0); value.extend(self.canonical()?); Ok(value)
    }
}
