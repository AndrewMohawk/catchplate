//! Initial issuance has a distinct sealed browser ingress and private-helper
//! preparation type. No old response/refresh statement is relabelled here.
use crate::native_currentness_v1 as current;
use crate::native_response_profile_v1::canonical_ascii_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const CHANNEL: &str = "catchplate.nativeOAuthExchangeChannel/v1";
pub const SCHEMA: &str = "catchplate.nativeOAuthExchangeStatement/v1";
pub const ATTESTATION_DOMAIN: &[u8] = b"catchplate/native-oauth-exchange-attestation/v1\0";
pub const SIGN_OPERATION: &str = "nativeOAuthExchange.sign/v1";
pub const HTTP_REQUEST: &str = "catchplate.nativeOAuthExchangeRequest/v1";
pub const HTTP_RESPONSE: &str = "catchplate.nativeOAuthExchangeResponse/v1";
pub(crate) use crate::native_oauth_refresh_v1::{ensure, sha};

pub(crate) fn fields(value: &Value, names: &[&str]) -> Result<(), String> {
    ensure(value.as_object().is_some_and(|map| map.len() == names.len() && names.iter().all(|name| map.contains_key(*name))), "initial issuance fields differ")
}

pub fn origin(value: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(value).map_err(|_| "native browser origin invalid")?;
    ensure(url.scheme() == "https" && url.host_str().is_some() && url.port_or_known_default() == Some(443)
        && url.username().is_empty() && url.password().is_none() && url.path() == "/" && url.query().is_none()
        && url.fragment().is_none() && url.origin().ascii_serialization() == value && value.len() <= 2048,
        "native browser origin must be an exact HTTPS authority")?;
    Ok(url)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Limits { pub pending_capacity: u64, pub revocation_capacity: u64 }
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Windows { pub contact_max_seconds: u64, pub retention_max_seconds: u64, pub pending_max_seconds: u64,
    pub operation_max_seconds: u64, pub recovery_max_seconds: u64 }
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Application { pub enrollment_original: String, pub material: Value, pub tls_roots_pem: String }
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub api_version: String, pub source_revision: String, pub authority_root_public_key: String,
    pub authority_root_spki_sha256: String, pub authority_configuration_original: String,
    pub control_plane_configuration_digest: String, pub deployment_id: String, pub instance_id: String,
    pub limits: Limits, pub windows: Windows, pub applications: BTreeMap<String, Application>,
    pub recovery_targets: Vec<String>, pub callback_origin: String, pub portal_origin: String,
    pub browser_vsock_port: u32,
}
impl Configuration {
    pub fn validate(&self) -> Result<(), String> {
        ensure(self.api_version == "catchplate.nativeOAuthExchangeConfiguration/v1" && current::identifier(&self.deployment_id)
            && current::digest(&self.authority_root_spki_sha256) && current::digest(&self.control_plane_configuration_digest)
            && self.instance_id.starts_with("spiffe://") && self.instance_id.len() <= 4096 && !self.instance_id.chars().any(char::is_control)
            && self.limits.pending_capacity == 64 && self.limits.revocation_capacity == 64
            && self.windows.contact_max_seconds == 600 && self.windows.retention_max_seconds == 600
            && self.windows.pending_max_seconds == 3600 && self.windows.operation_max_seconds == 30 && self.windows.recovery_max_seconds == 30
            && self.browser_vsock_port >= 1024 && self.browser_vsock_port < u32::MAX
            && self.callback_origin != self.portal_origin && !self.applications.is_empty() && self.applications.len() <= 2,
            "native initial-issuance configuration invalid")?;
        origin(&self.callback_origin)?; origin(&self.portal_origin)?;
        let root = current::bytes32(&self.authority_root_public_key)?;
        let mut spki = vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]; spki.extend(root);
        ensure(sha(&spki) == self.authority_root_spki_sha256, "issuance root pin differs")?;
        bounded_original(&self.authority_configuration_original, 1024 * 1024)?;
        for (provider, application) in &self.applications {
            ensure(matches!(provider.as_str(), "google" | "x") && application.material.is_object()
                && !application.tls_roots_pem.is_empty() && application.tls_roots_pem.len() <= 128 * 1024 && application.tls_roots_pem.is_ascii(),
                "native initial application inventory invalid")?;
            bounded_original(&application.enrollment_original, 32768)?;
        }
        ensure(self.recovery_targets.len() <= 64 && self.recovery_targets.windows(2).all(|pair| pair[0] < pair[1])
            && self.recovery_targets.iter().all(|item| current::uuid(item)), "initial recovery targets invalid")?;
        ensure(canonical_ascii_bytes(self)?.len() <= 2 * 1024 * 1024, "initial configuration bound")
    }
}
fn bounded_original(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let raw = URL_SAFE_NO_PAD.decode(value).map_err(|_| "initial original encoding")?;
    ensure(!raw.is_empty() && raw.len() <= maximum && URL_SAFE_NO_PAD.encode(&raw) == value, "initial original bound")?;
    Ok(raw)
}

/// Constructed only from the actual generated CA owner. The same Arc is
/// retained by the TLS listener, broker preparation and native statement.
pub struct BrowserTls {
    pub(crate) config: Arc<rustls::ServerConfig>, pub(crate) origin: String,
    pub(crate) certificate_sha: String, pub(crate) spki_sha: String,
    pub(crate) ca_sha: [u8; 32], pub(crate) deadline: u64, pub(crate) pid: libc::pid_t,
}
impl BrowserTls {
    pub fn config(&self) -> Arc<rustls::ServerConfig> { Arc::clone(&self.config) }
    pub fn origin(&self) -> &str { &self.origin }
    pub fn deadline(&self) -> u64 { self.deadline }
    pub fn check(&self, deadline: u64) -> Result<(), String> {
        ensure(unsafe { libc::getpid() } == self.pid && deadline <= self.deadline
            && crate::native_secret_broker_v1::now()? < deadline, "native browser TLS owner expired or changed")
    }
}

pub struct Prepared { arguments: Value, operation: String, issued: u64, expires: u64,
    config: Configuration, ingress: Arc<BrowserTls> }
pub enum Reply {
    Prepared(Prepared),
    DraftCookie { exchange_id: String, name: String, value: String, expires: u64 },
    Redirect { exchange_id: String, location: String },
    Complete { exchange_id: String, status: String, custody_sha: String },
}
impl Reply {
    pub(crate) fn parse(value: Value, config: &Configuration, ingress: &Arc<BrowserTls>) -> Result<Self, String> {
        ensure(value["apiVersion"] == CHANNEL, "initial helper channel differs")?;
        let phase = value["phase"].as_str().ok_or("initial helper phase")?;
        if phase == "prepared" {
            fields(&value, &["apiVersion","phase","operation","arguments","issuedAtEpochNs","expiresAtEpochNs"])?;
            let prepared = Prepared { arguments: value["arguments"].clone(), operation: value["operation"].as_str().ok_or("initial operation")?.to_owned(),
                issued: value["issuedAtEpochNs"].as_u64().ok_or("initial issue")?, expires: value["expiresAtEpochNs"].as_u64().ok_or("initial expiry")?,
                config: config.clone(), ingress: Arc::clone(ingress) };
            fields(&prepared.arguments, &["action","resource_id","payload_digest","actor_id","request","approval_id","credential_policy",
                "enrollment_original","control_plane_configuration_digest","assignment_original"])?;
            ensure(matches!(prepared.operation.as_str(), "oauth.measured-exchange.prepare" | "oauth.measured-exchange.claim" |
                "oauth.measured-exchange.capture" | "oauth.measured-exchange.stage" | "oauth.measured-exchange.recover" | "oauth.measured-exchange.cancel")
                && prepared.arguments["action"] == "credential.oauth.measured-consent" && prepared.arguments["approval_id"].is_null()
                && prepared.arguments["control_plane_configuration_digest"] == config.control_plane_configuration_digest
                && current::uuid(prepared.exchange_id()?) && prepared.arguments["request"]["exchangeId"] == prepared.exchange_id()?
                && prepared.expires > prepared.issued && prepared.expires - prepared.issued <= 30_000_000_000,
                "initial preparation is not closed")?;
            prepared.provider()?;
            Ok(Self::Prepared(prepared))
        } else {
            let id = value["exchangeId"].as_str().ok_or("initial helper exchange")?.to_owned();
            ensure(current::uuid(&id), "initial helper exchange invalid")?;
            match phase {
                "draft-cookie" => {
                    fields(&value, &["apiVersion","phase","exchangeId","cookieName","cookieValue","expiresAtEpochNs"])?;
                    let name = value["cookieName"].as_str().ok_or("native cookie name")?.to_owned();
                    let nonce = value["cookieValue"].as_str().ok_or("native cookie value")?.to_owned();
                    ensure(name == format!("__Host-catchplate-native-oauth-{}", id.replace('-', "")) && current::bytes32(&nonce).is_ok(), "native cookie differs")?;
                    Ok(Self::DraftCookie { exchange_id: id, name, value: nonce, expires: value["expiresAtEpochNs"].as_u64().ok_or("native cookie expiry")? })
                },
                "authorization-redirect" => {
                    fields(&value, &["apiVersion","phase","exchangeId","location"])?;
                    let location = value["location"].as_str().ok_or("native authorization URL")?.to_owned();
                    let url = url::Url::parse(&location).map_err(|_| "native authorization URL")?;
                    ensure(location.len() <= 16384 && url.scheme() == "https" && url.username().is_empty() && url.password().is_none()
                        && url.fragment().is_none() && url.port_or_known_default() == Some(443)
                        && matches!((url.host_str(),url.path()), (Some("accounts.google.com"),"/o/oauth2/v2/auth") | (Some("twitter.com"),"/i/oauth2/authorize")),
                        "native authorization endpoint differs")?;
                    Ok(Self::Redirect { exchange_id: id, location })
                },
                "complete" => {
                    fields(&value, &["apiVersion","phase","exchangeId","status","custodyRowSha256"])?;
                    let status = value["status"].as_str().ok_or("initial completion status")?.to_owned();
                    let digest = value["custodyRowSha256"].as_str().ok_or("initial custody original")?.to_owned();
                    ensure(matches!(status.as_str(),"staged"|"observed-staged"|"cancelled"|"captured-unusable") && current::digest(&digest), "initial completion differs")?;
                    Ok(Self::Complete { exchange_id: id, status, custody_sha: digest })
                },
                _ => Err("unknown native initial helper phase".to_owned()),
            }
        }
    }
}
impl Prepared {
    pub fn operation(&self) -> &str { &self.operation }
    pub fn exchange_id(&self) -> Result<&str,String> { self.arguments["resource_id"].as_str().ok_or_else(||"initial exchange absent".to_owned()) }
    pub fn provider(&self) -> Result<&str, String> {
        let encoded = self.arguments["enrollment_original"].as_str().ok_or("initial enrollment absent")?;
        let matches: Vec<_> = self.config.applications.iter().filter(|(_, app)| app.enrollment_original == encoded).collect();
        ensure(matches.len() == 1, "initial application assignment absent")?;
        Ok(matches[0].0.as_str())
    }
    pub(crate) fn ingress(&self) -> &BrowserTls { &self.ingress }
    pub(crate) fn statement(&self, boot: &str, key: &str, cp: &str, policy: &str, binary: &str) -> Result<Statement,String> {
        let raw = bounded_original(self.arguments["enrollment_original"].as_str().ok_or("initial enrollment")?,32768)?;
        let mut nonce = [0u8;32];
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new().fill(&mut nonce).map_err(|_|"initial evidence entropy")?;
        let phase = if self.operation.ends_with(".prepare") { "draft" } else { self.operation.rsplit('.').next().ok_or("initial phase")? };
        Ok(Statement(json!({"apiVersion":SCHEMA,"phase":phase,"holderId":current::holder_id(boot,key)?,"bootId":boot,"keyId":key,
            "controlPlaneResponseSigningKeyId":cp,"deploymentId":self.config.deployment_id,"instanceId":self.config.instance_id,
            "providerId":self.provider()?,"enrollmentSha256":sha(&raw),"exchangeId":self.exchange_id()?,"inputSha256":sha(&canonical_ascii_bytes(&self.arguments)?),
            "challenge":URL_SAFE_NO_PAD.encode(nonce),"policyHash":policy,"dataPlaneBinarySha256":binary,
            "callbackOrigin":self.ingress.origin,"portalOrigin":self.config.portal_origin,"ingressLeafCertificateSha256":self.ingress.certificate_sha,
            "ingressLeafSpkiSha256":self.ingress.spki_sha,"issuedAtEpochNs":self.issued,"expiresAtEpochNs":self.expires})))
    }
    pub fn wire(&self, evidence: Value) -> Result<Value,String> {
        ensure(evidence["statement"]["inputSha256"] == sha(&canonical_ascii_bytes(&self.arguments)?), "initial proof input changed")?;
        let mut args = self.arguments.clone(); args.as_object_mut().ok_or("initial arguments")?.insert("native_evidence".to_owned(), evidence);
        Ok(json!({"apiVersion":HTTP_REQUEST,"operation":self.operation,"arguments":args}))
    }
}
pub(crate) struct Statement(pub(crate) Value);
impl Statement {
    pub(crate) fn validate(&self, now:u64)->Result<(),String> {
        let start=self.0["issuedAtEpochNs"].as_u64().ok_or("initial issue time")?;
        let end=self.0["expiresAtEpochNs"].as_u64().ok_or("initial expiry")?;
        ensure(start<=now && now<end && end-start<=30_000_000_000,"initial statement expired")
    }
    pub(crate) fn canonical(&self)->Result<Vec<u8>,String>{canonical_ascii_bytes(&self.0)}
    pub(crate) fn preimage(&self)->Result<Vec<u8>,String>{let mut raw=SCHEMA.as_bytes().to_vec();raw.push(0);raw.extend(self.canonical()?);Ok(raw)}
}
