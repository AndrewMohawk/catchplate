//! Setup issuance has a distinct helper preparation, signing domain and original
//! session binding. Shared scalar/TLS types confer no old issuance permission.
use crate::native_currentness_v1 as current;
use crate::native_response_profile_v1::canonical_ascii_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const CHANNEL: &str = "catchplate.nativeOAuthSetupExchangeChannel/v1";
pub const SCHEMA: &str = "catchplate.nativeOAuthSetupExchangeStatement/v1";
pub const ATTESTATION_DOMAIN: &[u8] = b"catchplate/native-oauth-setup-exchange-attestation/v1\0";
pub const SIGN_OPERATION: &str = "nativeOAuthSetupExchange.sign/v1";
pub const HTTP_REQUEST: &str = "catchplate.nativeOAuthSetupExchangeRequest/v1";
pub const HTTP_RESPONSE: &str = "catchplate.nativeOAuthSetupExchangeResponse/v1";
pub(crate) use crate::native_oauth_refresh_v1::{ensure, sha};

pub(crate) fn fields(value: &Value, names: &[&str]) -> Result<(), String> {
    ensure(value.as_object().is_some_and(|map| map.len() == names.len() && names.iter().all(|name| map.contains_key(*name))), "Setup issuance fields differ")
}

// Data encodings and generated TLS ownership are shared, not signed purposes.
pub use crate::native_oauth_exchange_v1::{origin, Application, BrowserTls, Limits, Windows};
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct SetupLimits { pub setup_capacity: u64, pub setup_max_seconds: u64 }
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub api_version: String, pub source_revision: String, pub authority_root_public_key: String,
    pub authority_root_spki_sha256: String, pub authority_configuration_original: String,
    pub control_plane_configuration_digest: String, pub deployment_id: String, pub instance_id: String,
    pub limits: Limits, pub setup_limits: SetupLimits, pub windows: Windows, pub applications: BTreeMap<String, Application>,
    pub recovery_targets: Vec<String>, pub callback_origin: String, pub portal_origin: String,
    pub browser_vsock_port: u32,
}
impl Configuration {
    pub fn validate(&self) -> Result<(), String> {
        ensure(self.api_version == "catchplate.nativeOAuthSetupExchangeConfiguration/v1" && current::identifier(&self.deployment_id)
            && current::digest(&self.authority_root_spki_sha256) && current::digest(&self.control_plane_configuration_digest)
            && self.instance_id.starts_with("spiffe://") && self.instance_id.len() <= 4096 && !self.instance_id.chars().any(char::is_control)
            && self.limits.pending_capacity == 64 && self.limits.revocation_capacity == 64
            && self.setup_limits.setup_capacity == 64 && (300..=604800).contains(&self.setup_limits.setup_max_seconds)
            && self.windows.contact_max_seconds == 600 && self.windows.retention_max_seconds == 600
            && self.windows.pending_max_seconds == 3600 && self.windows.operation_max_seconds == 30 && self.windows.recovery_max_seconds == 30
            && self.browser_vsock_port >= 1024 && self.browser_vsock_port < u32::MAX
            && self.callback_origin != self.portal_origin && !self.applications.is_empty() && self.applications.len() <= 2,
            "native Setup-issuance configuration invalid")?;
        origin(&self.callback_origin)?; origin(&self.portal_origin)?;
        let root = current::bytes32(&self.authority_root_public_key)?;
        let mut spki = vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]; spki.extend(root);
        ensure(sha(&spki) == self.authority_root_spki_sha256, "issuance root pin differs")?;
        bounded_original(&self.authority_configuration_original, 1024 * 1024)?;
        for (provider, application) in &self.applications {
            ensure(matches!(provider.as_str(), "google" | "x") && application.material.is_object()
                && !application.tls_roots_pem.is_empty() && application.tls_roots_pem.len() <= 128 * 1024 && application.tls_roots_pem.is_ascii(),
                "native Setup application inventory invalid")?;
            bounded_original(&application.enrollment_original, 32768)?;
        }
        ensure(self.recovery_targets.len() <= 64 && self.recovery_targets.windows(2).all(|pair| pair[0] < pair[1])
            && self.recovery_targets.iter().all(|item| current::uuid(item)), "Setup recovery targets invalid")?;
        ensure(canonical_ascii_bytes(self)?.len() <= 2 * 1024 * 1024, "Setup configuration bound")
    }
}
fn bounded_original(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let raw = URL_SAFE_NO_PAD.decode(value).map_err(|_| "Setup original encoding")?;
    ensure(!raw.is_empty() && raw.len() <= maximum && URL_SAFE_NO_PAD.encode(&raw) == value, "Setup original bound")?;
    Ok(raw)
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
        ensure(value["apiVersion"] == CHANNEL, "Setup helper channel differs")?;
        let phase = value["phase"].as_str().ok_or("Setup helper phase")?;
        if phase == "prepared" {
            fields(&value, &["apiVersion","phase","operation","arguments","issuedAtEpochNs","expiresAtEpochNs"])?;
            let prepared = Prepared { arguments: value["arguments"].clone(), operation: value["operation"].as_str().ok_or("Setup operation")?.to_owned(),
                issued: value["issuedAtEpochNs"].as_u64().ok_or("Setup issue")?, expires: value["expiresAtEpochNs"].as_u64().ok_or("Setup expiry")?,
                config: config.clone(), ingress: Arc::clone(ingress) };
            fields(&prepared.arguments, &["action","resource_id","payload_digest","actor_id","request","approval_id","credential_policy",
                "enrollment_original","control_plane_configuration_digest","assignment_original"])?;
            ensure(matches!(prepared.operation.as_str(), "oauth.measured-setup.prepare" | "oauth.measured-setup.claim" |
                "oauth.measured-setup.capture" | "oauth.measured-setup.stage" | "oauth.measured-setup.recover" | "oauth.measured-setup.cancel")
                && prepared.arguments["action"] == "credential.oauth.measured-setup-consent" && prepared.arguments["approval_id"].is_null()
                && prepared.arguments["control_plane_configuration_digest"] == config.control_plane_configuration_digest
                && current::uuid(prepared.exchange_id()?) && prepared.arguments["request"]["exchangeId"] == prepared.exchange_id()?
                && prepared.expires > prepared.issued && prepared.expires - prepared.issued <= 30_000_000_000,
                "Setup preparation is not closed")?;
            prepared.provider()?; prepared.setup_binding()?;
            Ok(Self::Prepared(prepared))
        } else {
            let id = value["exchangeId"].as_str().ok_or("Setup helper exchange")?.to_owned();
            ensure(current::uuid(&id), "Setup helper exchange invalid")?;
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
                    let status = value["status"].as_str().ok_or("Setup completion status")?.to_owned();
                    let digest = value["custodyRowSha256"].as_str().ok_or("Setup custody original")?.to_owned();
                    ensure(matches!(status.as_str(),"staged"|"observed-staged"|"cancelled"|"captured-unusable") && current::digest(&digest), "Setup completion differs")?;
                    Ok(Self::Complete { exchange_id: id, status, custody_sha: digest })
                },
                _ => Err("unknown native Setup helper phase".to_owned()),
            }
        }
    }
}
impl Prepared {
    pub fn operation(&self) -> &str { &self.operation }
    pub fn exchange_id(&self) -> Result<&str,String> { self.arguments["resource_id"].as_str().ok_or_else(||"Setup exchange absent".to_owned()) }
    pub fn provider(&self) -> Result<&str, String> {
        let encoded = self.arguments["enrollment_original"].as_str().ok_or("Setup enrollment absent")?;
        let matches: Vec<_> = self.config.applications.iter().filter(|(_, app)| app.enrollment_original == encoded).collect();
        ensure(matches.len() == 1, "Setup application assignment absent")?;
        Ok(matches[0].0.as_str())
    }
    fn setup_binding(&self) -> Result<&Value, String> {
        let binding = &self.arguments["request"]["setupBinding"];
        fields(binding, &["sessionId","revision","rowSha256","ownerId","currentAssigneeId","expiresAtEpochNs"])?;
        let owner = binding["ownerId"].as_str().ok_or("Setup owner absent")?;
        ensure(current::uuid(binding["sessionId"].as_str().ok_or("Setup session absent")?)
            && binding["revision"].as_u64().is_some_and(|v| v <= 9_223_372_036_854_775_803)
            && current::digest(binding["rowSha256"].as_str().ok_or("Setup row hash absent")?)
            && owner.starts_with("oidc:") && owner.chars().count() <= 512 && !owner.chars().any(char::is_control)
            && self.arguments["actor_id"] == owner
            && (binding["currentAssigneeId"].is_null() || binding["currentAssigneeId"] == owner)
            && binding["expiresAtEpochNs"].as_u64().is_some_and(|v| self.expires <= v),
            "Setup preparation changed its initial owner, row or expiry")?;
        Ok(binding)
    }
    pub(crate) fn ingress(&self) -> &BrowserTls { &self.ingress }
    pub(crate) fn verify_ingress(&self, expected: &Arc<BrowserTls>, deadline: u64) -> Result<(), String> {
        ensure(Arc::ptr_eq(&self.ingress, expected), "Setup preparation belongs to another actual browser owner")?;
        self.ingress.check(deadline)
    }
    pub(crate) fn statement(&self, boot: &str, key: &str, cp: &str, policy: &str, binary: &str) -> Result<Statement,String> {
        let raw = bounded_original(self.arguments["enrollment_original"].as_str().ok_or("Setup enrollment")?,32768)?;
        let mut nonce = [0u8;32];
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new().fill(&mut nonce).map_err(|_|"Setup evidence entropy")?;
        let phase = if self.operation.ends_with(".prepare") { "draft" } else { self.operation.rsplit('.').next().ok_or("Setup phase")? };
        Ok(Statement(json!({"apiVersion":SCHEMA,"phase":phase,"holderId":current::holder_id(boot,key)?,"bootId":boot,"keyId":key,
            "controlPlaneResponseSigningKeyId":cp,"deploymentId":self.config.deployment_id,"instanceId":self.config.instance_id,
            "providerId":self.provider()?,"enrollmentSha256":sha(&raw),"exchangeId":self.exchange_id()?,"inputSha256":sha(&canonical_ascii_bytes(&self.arguments)?),
            "setupBindingSha256":sha(&canonical_ascii_bytes(self.setup_binding()?)?),
            "challenge":URL_SAFE_NO_PAD.encode(nonce),"policyHash":policy,"dataPlaneBinarySha256":binary,
            "callbackOrigin":self.ingress.origin,"portalOrigin":self.config.portal_origin,"ingressLeafCertificateSha256":self.ingress.certificate_sha,
            "ingressLeafSpkiSha256":self.ingress.spki_sha,"issuedAtEpochNs":self.issued,"expiresAtEpochNs":self.expires})))
    }
    pub fn wire(&self, evidence: Value) -> Result<Value,String> {
        ensure(evidence["statement"]["apiVersion"] == SCHEMA
            && evidence["statement"]["inputSha256"] == sha(&canonical_ascii_bytes(&self.arguments)?)
            && evidence["statement"]["setupBindingSha256"] == sha(&canonical_ascii_bytes(self.setup_binding()?)?),
            "Setup proof input or original binding changed")?;
        let mut args = self.arguments.clone(); args.as_object_mut().ok_or("Setup arguments")?.insert("native_evidence".to_owned(), evidence);
        Ok(json!({"apiVersion":HTTP_REQUEST,"operation":self.operation,"arguments":args}))
    }
}
pub(crate) struct Statement(pub(crate) Value);
impl Statement {
    pub(crate) fn validate(&self, now:u64)->Result<(),String> {
        let start=self.0["issuedAtEpochNs"].as_u64().ok_or("Setup issue time")?;
        let end=self.0["expiresAtEpochNs"].as_u64().ok_or("Setup expiry")?;
        ensure(start<=now && now<end && end-start<=30_000_000_000,"Setup statement expired")
    }
    pub(crate) fn canonical(&self)->Result<Vec<u8>,String>{canonical_ascii_bytes(&self.0)}
    pub(crate) fn preimage(&self)->Result<Vec<u8>,String>{let mut raw=SCHEMA.as_bytes().to_vec();raw.push(0);raw.extend(self.canonical()?);Ok(raw)}
}
